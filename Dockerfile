FROM python:3.10-slim

WORKDIR /app

# Копируем файл requirements.txt (он должен быть в корне проекта)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все файлы приложения (если есть другие файлы, их тоже нужно копировать)
COPY . /app

# Открываем порт 5000 для приложения
EXPOSE 5000

# Команда для запуска приложения
CMD ["python", "app.py"]
