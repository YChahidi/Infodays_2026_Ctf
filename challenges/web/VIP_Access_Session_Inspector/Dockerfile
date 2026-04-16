FROM python:3.9-slim
RUN useradd -m ctfuser
WORKDIR /home/ctfuser
RUN pip install flask pyjwt
RUN pip install flask
COPY app.py .
USER ctfuser
EXPOSE 5000
CMD ["python", "app.py"]
