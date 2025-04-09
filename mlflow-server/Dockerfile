# Use an official Python runtime as the base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Install MLflow and dependencies
RUN pip install mlflow

# Create directories for SQLite database and artifacts
RUN mkdir -p /app/mlflow-data /app/artifacts

# Expose the port MLflow runs on
EXPOSE 5000

# Command to run MLflow server
CMD ["mlflow", "server", "--backend-store-uri", "sqlite:///mlflow-data/mlflow.db", "--default-artifact-root", "/app/artifacts", "--host", "0.0.0.0", "--port", "5000"]