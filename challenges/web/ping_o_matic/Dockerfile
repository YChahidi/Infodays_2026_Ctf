FROM python:3.9-slim

# Create a user so we aren't running as root (Good Practice)
RUN useradd -m ctfuser
WORKDIR /home/ctfuser

# Install Flask
RUN pip install flask

# Copy the app and the flag
COPY app.py .
# The "Flag" is just a text file on the server
RUN echo "flag{infodays_cmnd_inj3ction_succ3ss}" > /flag.txt

USER ctfuser
EXPOSE 5000

CMD ["python", "app.py"]
