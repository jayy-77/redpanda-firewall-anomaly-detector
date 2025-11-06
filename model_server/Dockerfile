FROM python:3.11-slim

WORKDIR /app

COPY model_server/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY model_server/main.py ./main.py

ENV MODEL_PATH=/models/firewall_anomaly.joblib
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
