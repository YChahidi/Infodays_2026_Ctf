FROM python:3.9-slim
WORKDIR /app
COPY app.py stadium.db ./
RUN pip install flask
EXPOSE 8005
CMD ["python", "app.py"]
