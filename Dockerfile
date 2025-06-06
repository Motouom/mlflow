# Use an official Python runtime as the base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY app.py .

# Copy the .env file
COPY .env .

# Expose the port the app runs on
EXPOSE 5001

# Command to run the app
CMD ["python", "app.py"]