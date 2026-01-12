FROM python:3.9-slim

RUN useradd -m ctfuser
WORKDIR /home/ctfuser

RUN pip install flask
COPY app.py .

# The Flag
RUN echo "flag{infodays_traversal_master_2025}" > /etc/flag.txt

USER ctfuser
EXPOSE 5000
CMD ["python", "app.py"]
