import io
import json
import hashlib
from PIL import Image, ImageDraw, ImageFont
from datetime import datetime, timezone
from fastapi.responses import JSONResponse
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    pkcs12,
    Encoding,
    PrivateFormat,
    NoEncryption,
    load_pem_private_key,
)
from cryptography.x509 import NameOID
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from pyhanko import stamp  # type: ignore
from pyhanko.sign import signers, fields  # type: ignore
from pyhanko.pdf_utils import text, images, layout, incremental_writer  # type: ignore
from pyhanko.pdf_utils.font import opentype  # type: ignore


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime)):
        return obj.isoformat()
    raise TypeError("Type %s not serializable" % type(obj))


def create_response(success: bool, data=None, error=None, status_code=200):
    """
    Helper function to standardize all API responses.
    """
    return JSONResponse(
        content={
            "success": success,
            "data": json.loads(json.dumps(data, default=json_serial)),
            "error": json.loads(json.dumps(error, default=json_serial)),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        status_code=status_code,
    )


def add_header_to_pdf(input_pdf, output_pdf, header_text):
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    for page in reader.pages:
        # Get page dimensions
        width = float(page.mediabox.width)
        height = float(page.mediabox.height)

        # Create a PDF overlay with the header text
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=(width, height))

        # Set the font and size for the header text
        can.setFont("Helvetica", 6)
        # Set the color for the header text to light gray
        can.setFillColorRGB(0.75, 0.75, 0.75)

        # Adjust the header position dynamically (e.g., 20 points from the top)
        can.drawString(
            50, height - 20, header_text
        )  # 50 units from the top-left corner
        can.save()

        # Move to the beginning of the StringIO buffer
        packet.seek(0)

        # Read the overlay and merge it with the original page
        overlay = PdfReader(packet)
        page.merge_page(overlay.pages[0])
        writer.add_page(page)

    # Save the updated PDF to the output file
    with open(output_pdf, "wb") as output_file:
        writer.write(output_file)


def calculate_pdf_digest(file_path):
    """
    Calculate a digest of a PDF file using the specified hash algorithm.

    Parameters:
        file_path (str): Path to the PDF file.

    Returns:
        str: The hexadecimal digest of the file.
    """
    # Create a hash object
    hash_func = hashlib.new("sha3_256")

    try:
        # Read the file in binary mode and update the hash in chunks
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):  # Read in 8KB chunks
                hash_func.update(chunk)
        # Return the hex digest
        return hash_func.hexdigest()
    except FileNotFoundError:
        return f"File not found: {file_path}"
    except PermissionError:
        return f"Permission denied for file: {file_path}"
    except Exception as e:
        return f"An error occurred: {e}"


def generate_rsa_private_key(
    output_file: str = "private_key.pem", key_size: int = 2048
):
    """
    Generate an RSA private key and save it as an encrypted PEM file.

    Parameters:
        output_file (str): Output file path for the PEM file.
        key_size (int): Key size in bits (default: 2048).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )

    # Serialize private key with AES-256 encryption
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    # Save to file
    with open(output_file, "wb") as f:
        f.write(pem)

    return private_key


def load_private_key(private_key_path: str):
    """
    Load an RSA private key from a PEM file.

    Parameters:
        private_key_path (str): Path to the PEM file.

    Returns:
        RSAPrivateKey: The RSA private key object.
    """
    with open(private_key_path, "rb") as key_file:
        key_data = key_file.read()
        return load_pem_private_key(key_data, password=None, backend=default_backend())


def create_pkcs12_bundle(private_key, output_file_path, **kwargs):
    """
    Generate a self-signed X.509 certificate.
    Use this certificate and private key to create a PKCS#12 bundle.

    Args:
        private_key (RSAPrivateKey): RSA private key object.
        output_file_path (str): Path to save the PKCS#12 bundle.
        **kwargs: Additional subject attributes for the certificate.
    """
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs.get("country_name", "US")),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, kwargs.get("state", "California")
            ),
            x509.NameAttribute(
                NameOID.LOCALITY_NAME, kwargs.get("city", "San Francisco")
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, kwargs.get("organization", "N/A")
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME, kwargs.get("common_name", "localhost")
            ),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    p12 = pkcs12.serialize_key_and_certificates(
        "signature".encode(), private_key, cert, None, NoEncryption()
    )

    with open(output_file_path, "wb") as p12_file:
        p12_file.write(p12)


def resize_image(input_path, output_path):
    """
    Resizes an image to the specified width and height.

    Args:
        input_path (str): Path to the input image.
        output_path (str): Path to save the resized image.
    """
    try:
        with Image.open(input_path) as img:
            # Resize the image to the specified dimensions
            resized_img = img.resize((728, 328))
            # Save the resized image
            resized_img.save(output_path)
    except Exception as e:
        print(f"An error occurred: {e}")


def generate_handwriting_style_signature(text, font_path, output_path):
    """
    Generate a high-resolution image with text using a specific font.
    Background is white, text is black, and image size is 728x328 pixels.

    Args:
        text (str): The text to render.
        font_path (str): Path to the font file (.ttf or .otf).
        output_path (str): File path to save the output image.

    Returns:
        None: The function saves the generated image to the specified output path.
    """
    # Hardcoded settings
    image_size = (728, 328)  # Fixed image size
    bg_color = (255, 255, 255)  # White background
    text_color = (0, 0, 0)  # Black text
    font_size = 80  # Font size in points

    # Load the font
    font = ImageFont.truetype(font_path, font_size)

    # Create an image with the specified background color
    image = Image.new("RGBA", image_size, bg_color)
    draw = ImageDraw.Draw(image)

    # Calculate text position to center it
    text_bbox = draw.textbbox((0, 0), text, font=font)  # Get bounding box
    text_width = text_bbox[2] - text_bbox[0]  # Width of the text
    text_height = text_bbox[3] - text_bbox[1]  # Height of the text
    x = (image_size[0] - text_width) // 2
    y = (image_size[1] - text_height) // 2

    # Draw the text on the image
    draw.text((x, y), text, font=font, fill=text_color, anchor="lt")

    # Save the image
    image.save(output_path)


def add_signature(
    input_pdf_path,
    output_pdf_path,
    p12_path,
    signature_image_path,
    doc_id,
    stamp_font_path,
):
    """
    Adds a signature field named 'sign' to the last page of a PDF
    at a predefined position (bottom-right corner).

    :param input_pdf_path: Path to the input PDF file.
    :param output_pdf_path: Path to the output PDF file.
    :param p12_path: Path to the PKCS#12 keystore file.
    :param signature_image_path: Path to the visual signature image.
    :param doc_id: Document ID to be displayed in the signature.
    :param stamp_font_path: Path to the font file for the signature text.
    """
    field_name = "sign"

    # Determine the last page number (1-based index)
    with open(input_pdf_path, "rb") as pdf_in:
        reader = PdfReader(pdf_in)
        last_page = len(reader.pages)

    # Define the signature field specifications
    sig_field_spec = fields.SigFieldSpec(
        sig_field_name=field_name, on_page=last_page - 1, box=(375, 100, 525, 200)
    )

    # Load the PKCS#12 keystore
    signer = signers.SimpleSigner.load_pkcs12(p12_path)

    # Signature metadata
    signature_metadata = signers.PdfSignatureMetadata(field_name=field_name)

    # Add the signature field to the PDF
    with open(input_pdf_path, "rb") as pdf_in, open(output_pdf_path, "wb") as pdf_out:
        writer = incremental_writer.IncrementalPdfFileWriter(pdf_in)
        fields.append_signature_field(writer, sig_field_spec)
        out = signers.PdfSigner(
            signature_metadata,
            signer,
            stamp_style=stamp.TextStampStyle(
                background_opacity=1,
                stamp_text="Signed by: %(signer)s\nTime: %(ts)s\nDocument ID: %(doc)s",
                background=images.PdfImage(signature_image_path),
                background_layout=layout.SimpleBoxLayoutRule(
                    x_align=layout.AxisAlignment.ALIGN_MID,
                    y_align=layout.AxisAlignment.ALIGN_MIN,
                    margins=layout.Margins(10, 10, 10, 50),
                ),
                text_box_style=text.TextBoxStyle(
                    font=opentype.GlyphAccumulatorFactory(stamp_font_path),
                    box_layout_rule=layout.SimpleBoxLayoutRule(
                        x_align=layout.AxisAlignment.ALIGN_MID,
                        y_align=layout.AxisAlignment.ALIGN_MAX,
                        margins=layout.Margins(10, 10, 60, 10),
                    ),
                ),
            ),
        )
        out.sign_pdf(
            writer,
            output=pdf_out,
            appearance_text_params={"doc": doc_id},
        )
