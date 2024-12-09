import bson.objectid
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Cookie,
    File,
    UploadFile,
    Request,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import bson
import boto3
import modules.auth as auth
import modules.models as models
import modules.helpers as helpers
import modules.res_sdk.resdb_driver as resdb_driver


# Startup tasks
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load environment variables
    load_dotenv()

    # MongoDB setup
    MONGO_URI = os.getenv("MONGO_URI")
    DB_NAME = os.getenv("MONGO_DB_NAME")
    USERS_COLLECTION_NAME = os.getenv("MONGO_USERS_COLLECTION_NAME")
    DOCUMENTS_COLLECTION_NAME = os.getenv("MONGO_DOCUMENTS_COLLECTION_NAME")
    app.mongo = client = MongoClient(MONGO_URI)
    app.mongo.db = db = client[DB_NAME]
    app.mongo.db.users = db[USERS_COLLECTION_NAME]
    app.mongo.db.documents = db[DOCUMENTS_COLLECTION_NAME]

    # S3 setup
    S3_REGION = os.getenv("S3_REGION")
    S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY")
    S3_SECRET_KEY = os.getenv("S3_SECRET_KEY")
    app.s3 = boto3.client(
        "s3",
        region_name=S3_REGION,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
    )

    # ResDB setup
    RESDB_ROOT_URL = os.getenv("RESDB_ROOT_URL")
    app.resdb = resdb_driver.Resdb(RESDB_ROOT_URL)

    yield

    # Shutdown tasks
    # Close MongoDB connection
    client.close()


# FastAPI instance
app = FastAPI(lifespan=lifespan)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# JWT setup (for cookies)
COOKIE_EXPIRY = int(os.getenv("JWT_COOKIE_EXPIRY"))
COOKIE_NAME = "token"


# Endpoints
@app.get("/api")
async def read_root():
    return helpers.create_response(success=True, data={"message": "Hello, world!"})


@app.post("/api/register")
async def register_user(user: models.RegisterUser):
    # Check if user already exists
    if app.mongo.db.users.find_one({"email": user.email}):
        return helpers.create_response(
            success=False,
            error={"message": "Email already registered", "code": "REG001"},
            status_code=400,
        )

    # Check if all mandatory fields are provided
    if not all(
        [
            user.email,
            user.password,
            user.public_key,
            user.first_name,
            user.last_name,
            user.city,
            user.state,
            user.country_code,
        ]
    ):
        return helpers.create_response(
            success=False,
            error={"message": "Some mandatory fields are missing", "code": "REG002"},
            status_code=400,
        )

    # Hash password
    hashed_password = auth.hash_password(user.password)

    # Prepare user document
    user_doc = {
        "email": user.email,
        "password": hashed_password,
        "public_key": user.public_key,
        "name": {"first_name": user.first_name, "last_name": user.last_name},
        "city": user.city,
        "state": user.state,
        "country_code": user.country_code,
        "organization": user.organization if user.organization else "N/A",
        "last_login": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    # Insert into MongoDB
    app.mongo.db.users.insert_one(user_doc)

    # Generate RSA Private Key
    output_dir = f"{user.public_key}"
    output_file = f"{output_dir}/rsa_private.pem"
    os.makedirs(output_dir, exist_ok=True)
    helpers.generate_rsa_private_key(output_file=output_file)
    # Upload RSA Private Key to S3
    bucket = os.getenv("S3_BUCKET")
    s3_key = f"{user.public_key}/rsa_private.pem"
    app.s3.upload_file(output_file, bucket, s3_key)

    # Return success response
    return helpers.create_response(
        success=True, data={"message": "User registered successfully"}
    )


@app.post("/api/login")
async def login_user(user: models.LoginUser):
    # Find user by email
    db_user = app.mongo.db.users.find_one({"email": user.email})
    if not db_user:
        return helpers.create_response(
            success=False,
            error={"message": "Invalid credentials", "code": "AUTH001"},
            status_code=400,
        )

    # Verify password
    if not auth.verify_password(user.password, db_user["password"]):
        return helpers.create_response(
            success=False,
            error={"message": "Invalid credentials", "code": "AUTH002"},
            status_code=400,
        )

    # Create JWT
    token = auth.create_jwt(user.email)

    # Update last login
    app.mongo.db.users.update_one(
        {"email": user.email}, {"$set": {"last_login": datetime.now(timezone.utc)}}
    )

    response = helpers.create_response(
        success=True, data={"message": "Login successful"}
    )
    # Set cookie
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=False,
        secure=True if os.getenv("ENVIRONMENT") == "production" else False,
        max_age=COOKIE_EXPIRY * 24 * 60 * 60,
        samesite="strict" if os.getenv("ENVIRONMENT") == "production" else "none",
    )
    return response


@app.post("/api/logout")
async def logout_user():
    # Clear the cookie
    response = helpers.create_response(
        success=True, data={"message": "Logout successful"}
    )
    response.delete_cookie(key=COOKIE_NAME)
    return response


@app.get("/api/me")
async def get_authenticated_user_details(token: str = Cookie(None)):
    """
    Retrieves details of the authenticated user, except the password.
    """
    if not token:
        return helpers.create_response(
            success=False,
            error={"message": "Not authenticated", "code": "AUTH003"},
            status_code=401,
        )

    try:
        decoded_token = auth.decode_jwt(token)
    except HTTPException as e:
        return helpers.create_response(
            success=False, error={"message": str(e)}, status_code=401
        )
    email = decoded_token.get("sub")

    # Find user by email
    db_user = app.mongo.db.users.find_one({"email": email})
    if not db_user:
        return helpers.create_response(
            success=False,
            error={"message": "User not found", "code": "USER001"},
            status_code=404,
        )

    # Exclude sensitive fields
    db_user.pop("password", None)
    db_user.pop("_id", None)

    return helpers.create_response(success=True, data=db_user)


@app.post("/api/sign/initial")
async def sign_initial(user: models.SignInitial, token: str = Cookie(None)):
    if not token:
        return helpers.create_response(
            success=False,
            error={"message": "Not authenticated", "code": "AUTH003"},
            status_code=401,
        )

    try:
        decoded_token = auth.decode_jwt(token)
    except HTTPException as e:
        return helpers.create_response(
            success=False, error={"message": str(e)}, status_code=401
        )
    email = decoded_token.get("sub")

    # Find user by email
    db_user = app.mongo.db.users.find_one({"email": email})
    if not db_user:
        return helpers.create_response(
            success=False,
            error={"message": "User not found", "code": "USER001"},
            status_code=404,
        )

    # Verify password
    if not auth.verify_password(user.password, db_user["password"]):
        return helpers.create_response(
            success=False,
            error={"message": "Incorrect Password", "code": "AUTH002"},
            status_code=400,
        )

    return helpers.create_response(
        success=True, data={"public_key": db_user.get("public_key")}
    )


@app.post("/api/sign/prepare")
def sign_prepare(file: UploadFile = File(...), token: str = Cookie(None)):
    if not token:
        return helpers.create_response(
            success=False,
            error={"message": "Not authenticated", "code": "AUTH003"},
            status_code=401,
        )

    try:
        decoded_token = auth.decode_jwt(token)
    except HTTPException as e:
        return helpers.create_response(
            success=False, error={"message": str(e)}, status_code=401
        )
    email = decoded_token.get("sub")
    # get public key
    db_user = app.mongo.db.users.find_one({"email": email})
    if not db_user:
        return helpers.create_response(
            success=False,
            error={"message": "User not found", "code": "USER001"},
            status_code=404,
        )
    public_key = db_user.get("public_key")

    session_id = str(bson.ObjectId())
    os.makedirs(f"{session_id}", exist_ok=True)

    # download the file locally
    input_file_path = f"{session_id}/{file.filename}"
    with open(input_file_path, "wb") as f:
        f.write(file.file.read())

    # upload the file to S3
    bucket = os.getenv("S3_BUCKET")
    s3_key = f"{public_key}/documents/original/{file.filename}"
    app.s3.upload_file(input_file_path, bucket, s3_key)

    # get the document id by calculating the digest
    document_id = helpers.calculate_pdf_digest(input_file_path)

    # check if the document already exists in the database
    if app.mongo.db.documents.find_one({"document_id": document_id}):
        return helpers.create_response(
            success=False,
            error={"message": "Document already exists", "code": "SIGN002"},
            status_code=400,
        )

    # add document id and public key to the header of each page
    header_text = f"Document ID: {document_id} | Public Key: {public_key}"
    helpers.add_header_to_pdf(input_file_path, input_file_path, header_text)

    # Download the RSA private key from S3
    rsa_private_key_path = f"{session_id}/rsa_private.pem"
    s3_key = f"{public_key}/rsa_private.pem"
    app.s3.download_file(bucket, s3_key, rsa_private_key_path)
    rsa_private_key = helpers.load_private_key(rsa_private_key_path)

    # Generate the p12 file
    p12_path = f"{session_id}/signature.p12"
    full_name = f"{db_user.get('name').get('first_name')} {db_user.get('name').get('last_name')}"
    helpers.create_pkcs12_bundle(
        rsa_private_key,
        p12_path,
        country_name=db_user.get("country_code"),
        state=db_user.get("state"),
        city=db_user.get("city"),
        organization=db_user.get("organization"),
        common_name=full_name,
    )

    # Generate handwriting style signature
    initials = (
        db_user.get("name").get("first_name")[0]
        + db_user.get("name").get("last_name")[0]
    )
    font_path = "modules/fonts/Rockybilly.ttf"
    signature_path = f"{session_id}/signature.png"
    helpers.generate_handwriting_style_signature(initials, font_path, signature_path)

    # attach signature to the file
    output_file_path = f"{session_id}/signed-{file.filename}"
    stamp_font_path = "modules/fonts/NotoSans-Regular.ttf"
    helpers.add_signature(
        input_file_path,
        output_file_path,
        p12_path,
        signature_path,
        document_id,
        stamp_font_path,
    )

    # upload the signed file to S3
    s3_key = f"{public_key}/documents/signed/{document_id}.pdf"
    app.s3.upload_file(output_file_path, bucket, s3_key)

    # upload the signature p12 to S3
    s3_key = f"{public_key}/documents/signed/signature.p12"
    app.s3.upload_file(p12_path, bucket, s3_key)

    # calculate the digest
    document_digest = helpers.calculate_pdf_digest(output_file_path)

    # prepare the transaction
    pdf_token = {
        "data": {
            "document_id": document_id,
            "document_digest": document_digest,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }
    prepared_token_tx = app.resdb.transactions.prepare(
        operation="CREATE",
        signers=public_key,
        asset=pdf_token,
    )

    # update the document status to prepared
    app.mongo.db.documents.insert_one(
        {
            "document_id": document_id,
            "s3_path": {"bucket": bucket, "key": s3_key},
            "public_key": public_key,
            "status_flag": 1,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
    )

    # remove the temporary files. everything inside {session_id}
    for root, dirs, files in os.walk(f"{session_id}", topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(f"{session_id}")

    return helpers.create_response(
        success=True,
        data=prepared_token_tx,
    )


@app.post("/api/sign/commit")
async def sign_commit(request: Request, token: str = Cookie(None)):
    if not token:
        return helpers.create_response(
            success=False,
            error={"message": "Not authenticated", "code": "AUTH003"},
            status_code=401,
        )

    try:
        decoded_token = auth.decode_jwt(token)
    except HTTPException as e:
        return helpers.create_response(
            success=False, error={"message": str(e)}, status_code=401
        )
    email = decoded_token.get("sub")
    # get public key
    db_user = app.mongo.db.users.find_one({"email": email})
    if not db_user:
        return helpers.create_response(
            success=False,
            error={"message": "User not found", "code": "USER001"},
            status_code=404,
        )
    public_key = db_user.get("public_key")

    # get the transaction from the request
    transaction = await request.json()

    # commit the transaction
    app.resdb.transactions.send_commit(transaction)

    # update the document status to signed
    res_id = transaction.pop("id")
    document_id = transaction.get("asset").get("data").get("document_id")
    app.mongo.db.documents.update_one(
        {"document_id": document_id},
        {
            "$set": {
                "status_flag": 2,
                "res_db": {"res_id": res_id, "transaction": transaction},
                "updated_at": datetime.now(timezone.utc),
            }
        },
    )

    # get the signed document from S3 and return it as a byte stream
    bucket = os.getenv("S3_BUCKET")
    s3_key = f"{public_key}/documents/signed/{document_id}.pdf"
    signed_document = app.s3.get_object(Bucket=bucket, Key=s3_key)
    signed_document_body = signed_document["Body"].read()

    return Response(
        content=signed_document_body,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={document_id[:8]}.pdf"},
    )


@app.post("/api/sign/verify")
async def verify_signature(file: UploadFile = File(...), token: str = Cookie(None)):
    if not token:
        return helpers.create_response(
            success=False,
            error={"message": "Not authenticated", "code": "AUTH003"},
            status_code=401,
        )

    try:
        decoded_token = auth.decode_jwt(token)
    except HTTPException as e:
        return helpers.create_response(
            success=False, error={"message": str(e)}, status_code=401
        )
    email = decoded_token.get("sub")
    # get public key
    db_user = app.mongo.db.users.find_one({"email": email})
    if not db_user:
        return helpers.create_response(
            success=False,
            error={"message": "User not found", "code": "USER001"},
            status_code=404,
        )

    session_id = str(bson.ObjectId())
    os.makedirs(f"{session_id}", exist_ok=True)

    # download the file locally
    input_file_path = f"{session_id}/{file.filename}"
    with open(input_file_path, "wb") as f:
        f.write(file.file.read())

    # calculate the digest
    document_digest = helpers.calculate_pdf_digest(input_file_path)

    # find in resdb
    record = app.resdb.transactions.retrieve(document_digest)
    # record might be '' or a dict. if it is a dict, it is the transaction, if it is '', the document could not be found
    if record == "":
        return helpers.create_response(
            success=False,
            error={"message": "Document not found", "code": "SIGN001"},
            status_code=404,
        )

    # get the owner of the document
    owner = record.get("inputs")[0].get("owners_before")[0]
    owner_details = app.mongo.db.users.find_one(
        {"public_key": owner},
        {"name": 1, "country_code": 1, "organization": 1, "_id": 0},
    )
    document_id = record.get("asset").get("data").get("document_id")
    timestamp = record.get("asset").get("data").get("timestamp")
    timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z").strftime(
        "%B %d, %Y, %H:%M:%S"
    )
    timestamp += " UTC"
    required_text = f"Owner: {owner_details.get('name').get('first_name')} {owner_details.get('name').get('last_name')}"
    required_text += f"\nCountry: {owner_details.get('country_code')}"
    if owner_details.get("organization") and owner_details.get("organization") != "N/A":
        required_text += f"\nOrganization: {owner_details.get('organization')}"
    required_text += f"\nSigned at: {timestamp}"

    # remove the temporary files. everything inside {session_id}
    for root, dirs, files in os.walk(f"{session_id}", topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(f"{session_id}")

    return helpers.create_response(
        success=True,
        data={"ownership": required_text, "document_id": document_id},
    )


# Run the FastAPI app
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
