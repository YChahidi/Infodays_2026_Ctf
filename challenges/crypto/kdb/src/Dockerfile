FROM python:3.12-slim

WORKDIR /app

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/protocol.py src/server.py /app/
COPY flag.txt /app/flag.txt

ENV PORT=9001
EXPOSE 9001

CMD ["python3", "-u", "server.py"]
