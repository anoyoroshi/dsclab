FROM python:3.13.1-slim

RUN apt-get update && apt-get install -y gettext
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

