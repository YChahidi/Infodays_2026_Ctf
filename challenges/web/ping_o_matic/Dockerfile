FROM python:3.9-slim

WORKDIR /app
COPY app.py .
RUN pip install flask

# Install ping command
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

# Create flag file
RUN echo "INFODAYS{CMD_INJ3CT10N_W4F_BYP4SS_2026}" > /flag.txt

EXPOSE 5000
CMD ["python", "app.py"]
