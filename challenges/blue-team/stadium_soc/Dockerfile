FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY gen.py .
RUN python3 gen.py
COPY app.py .
COPY templates/ templates/
COPY static/ static/
EXPOSE 5000
CMD ["python3", "app.py"]
