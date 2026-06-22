FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

# Install existing requirements, plus django and common REST framework packages just in case they are missing
RUN pip install --no-cache-dir -r requirements.txt django djangorestframework django-cors-headers python-dotenv PyJWT psycopg2-binary Pillow stripe

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn core.wsgi:application --bind 0.0.0.0:${PORT:-8000}"]
