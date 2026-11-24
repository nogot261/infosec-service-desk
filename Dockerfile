FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=10000
COPY . /app
RUN pip install --no-cache-dir -r requirements-deploy.txt
EXPOSE 10000
CMD ["sh", "-c", "exec gunicorn wsgi:app --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 2 --timeout 60"]
