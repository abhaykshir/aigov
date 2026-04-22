FROM pytorch/pytorch:2.2.0-cuda11.8-cudnn8-runtime AS base

WORKDIR /app

COPY models/sentiment_classifier.onnx /app/models/
COPY models/embeddings.safetensors /app/models/

RUN pip install --no-cache-dir \
    transformers==4.38.0 \
    flask==3.0.0 \
    gunicorn==21.2.0

COPY src/ /app/src/

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "src.app:app"]
