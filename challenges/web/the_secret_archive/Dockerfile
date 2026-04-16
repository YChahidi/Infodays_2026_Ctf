FROM python:3.9-slim

# Create a non-root user for security
RUN useradd -m ctfuser
WORKDIR /home/ctfuser

# Install dependencies - keeping it lightweight
RUN pip install --no-cache-dir flask

# Copy only the essential application files
COPY app.py .
COPY news.txt .
COPY static ./static

# THE DYNAMIC PART:
# Copy the flag from your local folder to /tmp/ to force path traversal
COPY flag.txt /tmp/the_real_flag.txt

# Security: Ensure ctfuser owns the app directory
RUN chown -R ctfuser:ctfuser /home/ctfuser

USER ctfuser
EXPOSE 5000

CMD ["python", "app.py"]
