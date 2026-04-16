FROM python:3.9-slim
RUN useradd -m ctfuser
WORKDIR /home/ctfuser
RUN pip install flask
COPY app.py .
COPY static ./static
USER ctfuser
EXPOSE 5000
CMD ["python", "app.py"]
