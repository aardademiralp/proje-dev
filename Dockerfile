# --- 1. AŞAMA: Rust Core Engine Derleme Alanı ---
FROM rust:1.75-slim AS rust-builder
WORKDIR /app
COPY src/core_engine .
RUN cargo build --release

# --- 2. AŞAMA: Çalışma ve Orkestrasyon Alanı ---
FROM python:3.10-slim
WORKDIR /app

# Sistem bağımlılıklarını yükleyelim (Ağ araçları ve derlenmiş Rust motoru için gerekli kütüphaneler)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python bağımlılıklarını kopyalayıp yükleyelim
COPY src/orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Projenin kaynak kodlarını ve test katmanını konteynere aktaralım
COPY src/ /app/src/

# İlk aşamada derlediğimiz yüksek performanslı Rust motorunu Python'ın erişebileceği yere taşıyalım
COPY --from rust-builder /app/target/release/core_engine /app/src/orchestrator/

# Çıktıların yazılacağı rapor klasörünü hazırlayalım
RUN mkdir -p /app/reports

# FastAPI'nin çalışacağı portu dışarı açalım
EXPOSE 8000

# Uygulamayı başlatalım
CMD ["uvicorn", "src.orchestrator.main:app", "--host", "0.0.0.0", "--port", "8000"]
