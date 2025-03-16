# Use an official Python runtime as a parent image
FROM python:3.11-slim-bookworm

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source code into the container at /app
COPY . .

# Set environment variables (if needed)
ENV FLASK_APP=app.py
ENV FLASK_DEBUG=1

# Expose port 5000
EXPOSE 5000

# Define the command to run the application
CMD ["flask", "run", "--host=0.0.0.0"]