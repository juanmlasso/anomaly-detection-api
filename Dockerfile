FROM python:3.11-slim

WORKDIR /app

# Copiar e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Generar dataset y entrenar modelo en tiempo de build
RUN python -m app.generate_dataset && python -m app.train_model

# Exponer puerto
EXPOSE 8000

# Ejecutar servidor
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
