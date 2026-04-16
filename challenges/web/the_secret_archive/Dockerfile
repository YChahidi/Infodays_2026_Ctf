FROM python:3.9-slim

RUN useradd -m ctfuser
WORKDIR /home/ctfuser

RUN pip install --no-cache-dir flask

COPY app.py .
COPY news.txt .

# Create the directory structure
RUN mkdir -p /opt/archive/classified

# Copy flag to the location mentioned in changelog
COPY flag.txt /opt/archive/classified/flag.txt

RUN chown -R ctfuser:ctfuser /home/ctfuser /opt/archive

USER ctfuser
EXPOSE 5000

CMD ["python", "app.py"]
