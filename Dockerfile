FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
COPY scanner/ ./scanner
COPY rules/ ./rules
RUN pip install --no-cache-dir ./scanner

EXPOSE 8000

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh
CMD ["/app/start.sh"]
