FROM python:3.9-slim

RUN useradd -m ctfuser && \
    mkdir -p /home/ctfuser /tmp/backups /tmp/reports && \
    chown -R ctfuser:ctfuser /home/ctfuser /tmp/backups /tmp/reports

WORKDIR /home/ctfuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN chown -R ctfuser:ctfuser /home/ctfuser

USER ctfuser
EXPOSE 5000

CMD ["python", "app.py"]
