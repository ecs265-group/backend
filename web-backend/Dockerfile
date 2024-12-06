FROM python:3.10

# Set the working directory
WORKDIR /app

# Copy requirements.txt
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy the rest of the code
COPY . .

# Run the server
CMD ["python3", "-u", "app.py"]