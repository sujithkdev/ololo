FROM python:3.11-slim
WORKDIR /app
COPY shared /app/shared
COPY server /app/server
RUN pip install --no-cache-dir ./shared ./server \
    && useradd --uid 10001 --create-home behedr \
    && mkdir -p /var/lib/behedr /var/log/behedr \
    && chown -R behedr:behedr /var/lib/behedr /var/log/behedr
ENV EDR_DATA_DIR=/var/lib/behedr EDR_LOG_DIR=/var/log/behedr EDR_HOST=0.0.0.0
USER behedr
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"
CMD ["python", "-m", "behedr_server"]
