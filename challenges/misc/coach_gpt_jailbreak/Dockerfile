FROM registry.digitalocean.com/infodays-registry/base:web

USER root

RUN apk add --no-cache bash

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY chatbot.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

USER 1000

EXPOSE 8080

CMD ["./entrypoint.sh"]
