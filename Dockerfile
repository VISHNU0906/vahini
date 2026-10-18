FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[service]"
RUN useradd --create-home vahini
USER vahini
EXPOSE 8080
CMD ["vahini", "serve", "--host", "0.0.0.0", "--port", "8080"]
