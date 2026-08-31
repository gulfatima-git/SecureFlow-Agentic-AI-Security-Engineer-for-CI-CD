# Base image
FROM python:3.12-slim

ENV NODE_ENV=production
ENV DATABASE_PASSWORD=supersecret

WORKDIR /app

RUN curl -sSL https://example.invalid/install.sh | bash

COPY . .

CMD ["python", "app.py"]
