FROM python:3.12-slim

# Signals: docker stop → graceful flask shutdown
STOPSIGNAL SIGTERM

# No apt build deps needed: psutil, flask and Pillow are pure Python wheels.
RUN pip install --no-cache-dir flask==3.* psutil==6.* Pillow==11.*

WORKDIR /app

COPY server/ /app/

ENV MTMON_PORT=8080 \
    MTMON_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# /app/data holds the sqlite DB → mount as a volume to keep data between redeploys
VOLUME ["/app/data"]

EXPOSE 8080

# alerts.py runs as a loop in the same process? No — it is a background thread inside
# app.py (MetricsThread). If you prefer a separate container, comment this line and use
# the compose 'alerts' service instead.
CMD ["python3", "app.py"]
