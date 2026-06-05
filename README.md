<div align="center">

```
██╗███████╗██╗   ██╗    ███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║██╔════╝██║   ██║    ██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║███████╗██║   ██║    ███████╗█████╗  ██║     ██║   ██║██████╔╝███████╗
██║╚════██║██║   ██║    ╚════██║██╔══╝  ██║     ██║   ██║██╔═══╝ ╚════██║
██║███████║╚██████╔╝    ███████║███████╗╚██████╗╚██████╔╝██║     ███████║
╚═╝╚══════╝ ╚═════╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
                          O R C H E S T R A T O R
```

**ISU-SecOps-Orchestrator**

*SOAR (Security Orchestration, Automation, and Response) Tabanlı*
*Modüler Otomatik Güvenlik Keşfi ve Raporlama Hattı*

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Rust](https://img.shields.io/badge/Rust-Core_Engine-CE422B?style=for-the-badge&logo=rust&logoColor=white)](https://rust-lang.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-orange?style=for-the-badge)](https://owasp.org/www-project-top-ten/)

</div>

---

## 📖 Proje Genel Bakış

**ISU-SecOps-Orchestrator**, endüstriyel kalitede bir **SOAR** (Security Orchestration, Automation, and Response) sisteminin uçtan uca referans implementasyonudur.

Proje, iki temel katmandan oluşur:

| Katman | Teknoloji | Sorumluluk |
|--------|-----------|------------|
| **Core Engine** | Rust (Vize Projesi) | Yüksek performanslı ağ/port tarama, servis tespiti |
| **Orchestrator** | Python / FastAPI | İş akışı yönetimi, raporlama, REST API |

Bu ayrım, modern **polyglot architecture** yaklaşımının pratiğe dökülmüş halidir: Her katman, kendi alanındaki en iyi araçla inşa edilmiştir.

---

## 🏛️ Mimari

### Sistem Mimarisi

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ISU-SecOps-Orchestrator                         │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                       REST API Katmanı                           │   │
│  │                                                                  │   │
│  │   POST /api/v1/scan          GET /api/v1/scan/{id}              │   │
│  │   GET  /api/v1/reports       GET /api/v1/health                 │   │
│  │                                                                  │   │
│  │              FastAPI + Pydantic + CORS Middleware                │   │
│  └────────────────────────┬─────────────────────────────────────────┘   │
│                           │                                             │
│                     BackgroundTasks                                     │
│                           │                                             │
│  ┌────────────────────────▼─────────────────────────────────────────┐   │
│  │                   Orchestrator Katmanı                           │   │
│  │                                                                  │   │
│  │  ┌─────────────────────┐    ┌─────────────────────────────────┐  │   │
│  │  │   scanner.py        │    │       reporter.py               │  │   │
│  │  │                     │    │                                 │  │   │
│  │  │  RustEngineWrapper  │───▶│  VulnerabilityReportGenerator   │  │   │
│  │  │  ┌───────────────┐  │    │  ┌─────────────────────────┐   │  │   │
│  │  │  │ asyncio.create│  │    │  │ OWASP Top 10 Mapping    │   │  │   │
│  │  │  │ _subprocess   │  │    │  │ CVE References          │   │  │   │
│  │  │  │ _exec()       │  │    │  │ Risk Scoring (CVSS)     │   │  │   │
│  │  │  │               │  │    │  │ Markdown Generation     │   │  │   │
│  │  │  │ Timeout Guard │  │    │  │ Timestamp File Save     │   │  │   │
│  │  │  └───────────────┘  │    │  └─────────────────────────┘   │  │   │
│  │  └─────────────────────┘    └─────────────────────────────────┘  │   │
│  └────────────────────────┬─────────────────────────────────────────┘   │
│                           │                                             │
│  ┌────────────────────────▼─────────────────────────────────────────┐   │
│  │                    Core Engine Katmanı                           │   │
│  │                                                                  │   │
│  │              isu-secops-engine (Rust Binary)                    │   │
│  │                                                                  │   │
│  │   • TCP/UDP Port Tarama          • Servis Tespiti               │   │
│  │   • Banner Grabbing              • OS Detection                 │   │
│  │   • JSON / Text Çıktı           • Async I/O (Tokio)            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Raporlama Çıktısı                             │   │
│  │                                                                  │   │
│  │  reports/                                                        │   │
│  │  └── isu_secops_192-168-1-1_20260604_191500.md                  │   │
│  │      ├── Executive Summary (Yönetici Özeti)                      │   │
│  │      ├── Technical Findings (OWASP + CVE Ref.)                  │   │
│  │      ├── Risk Matrix (CVSS-benzeri Skorlama)                    │   │
│  │      └── Remediation Guide (Sıkılaştırma Önerileri)            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Uygulama Akışı (Request Lifecycle)

```
İstemci                 FastAPI              BackgroundTasks          Engine
   │                      │                        │                    │
   │  POST /scan          │                        │                    │
   │─────────────────────▶│                        │                    │
   │                      │ task_id oluştur        │                    │
   │                      │ Task Store'a ekle      │                    │
   │                      │──────────────────────▶│                    │
   │                      │                        │ asyncio subprocess │
   │  202 Accepted        │                        │───────────────────▶│
   │◀─────────────────────│                        │                    │
   │  {task_id, status}   │                        │   JSON/Text output │
   │                      │                        │◀───────────────────│
   │                      │                        │ Parse → HostInfo   │
   │  GET /scan/{id}      │                        │ Generate Report    │
   │─────────────────────▶│ Task Store'dan oku     │                    │
   │  200 {COMPLETED}     │◀──────────────────────│                    │
   │◀─────────────────────│                        │                    │
   │                      │                        │                    │
```

---

## 🧠 Neden Rust + Python Kombinasyonu?

Bu mimari tercih, **"doğru araç, doğru iş"** ilkesini yansıtır:

### Rust — Core Engine

| Özellik | Rust Avantajı |
|---------|---------------|
| **Performans** | C/C++ seviyesi hız, sıfır çalışma zamanı maliyeti. Binlerce port'u milisaniyeler içinde tarar. |
| **Güvenlik** | Bellek güvenliği garantisi (ownership sistemi). Buffer overflow, use-after-free yok. |
| **Eşzamanlılık** | Tokio async runtime ile binlerce eşzamanlı ağ bağlantısı. |
| **Binary Dağıtım** | Tek bağımsız binary; Python/JVM/Node gibi runtime gerektirmez. |
| **Sistem Erişimi** | Raw socket, ICMP, düşük seviye ağ işlemleri için ideal. |

### Python/FastAPI — Orchestrator

| Özellik | Python/FastAPI Avantajı |
|---------|-------------------------|
| **Geliştirme Hızı** | Hızlı prototipleme, zengin ekosistem. |
| **asyncio** | I/O-bound işler (HTTP, subprocess yönetimi) için ideal. |
| **Tip Güvenliği** | Pydantic ile runtime tip doğrulaması. |
| **Belgeleme** | FastAPI → otomatik OpenAPI/Swagger UI. |
| **Test Ekosistemi** | pytest, httpx, unittest.mock ile kapsamlı test. |
| **Raporlama** | Metin işleme, şablon oluşturma Python'da çok daha kolay. |

### Entegrasyon Noktası

```rust
// Rust binary standart JSON formatında çıktı verir:
println!("{}", serde_json::to_string(&scan_results)?);
```

```python
# Python asyncio ile non-blocking çağrı:
process = await asyncio.create_subprocess_exec(
    "isu-secops-engine", "--target", target, "--format", "json",
    stdout=asyncio.subprocess.PIPE,
)
stdout, _ = await asyncio.wait_for(process.communicate(), timeout=120)
```

---

## 📁 Proje Yapısı

```
ISU-SecOps-Orchestrator/
│
├── core_engine/                   # Rust Vize Projesi
│   └── isu-secops-engine          # Derlenmiş binary buraya yerleştirilir
│
├── orchestrator/                  # Python/FastAPI Katmanı
│   ├── app/
│   │   ├── __init__.py            # Paket tanımı, versiyon bilgisi
│   │   ├── main.py                # FastAPI app, router, global handlers
│   │   ├── config.py              # Pydantic BaseSettings konfigürasyonu
│   │   ├── scanner.py             # Rust binary async yöneticisi
│   │   ├── reporter.py            # Markdown rapor üretici motoru
│   │   └── utils.py               # Loglama, validasyon, yardımcılar
│   └── requirements.txt           # Python bağımlılıkları
│
├── tests/
│   ├── __init__.py
│   └── test_orchestrator.py       # Kapsamlı pytest test paketi
│
├── reports/                       # Üretilen Markdown raporları (otomatik)
│
├── pyproject.toml                 # Proje metadata ve araç konfigürasyonları
└── README.md                      # Bu dosya
```

---

## 🚀 Kurulum ve Başlatma

### Ön Gereksinimler

- **Python 3.11+**
- **Rust toolchain** (vize projesinin derlenmesi için, opsiyonel)
- **pip veya uv** paket yöneticisi

### 1. Projeyi Klonlayın

```bash
git clone https://github.com/your-username/ISU-SecOps-Orchestrator.git
cd ISU-SecOps-Orchestrator
```

### 2. Python Sanal Ortamı Oluşturun

```bash
# Sanal ortam oluştur
python -m venv .venv

# Aktive edin
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.venv\Scripts\Activate.ps1
```

### 3. Bağımlılıkları Yükleyin

```bash
pip install -r orchestrator/requirements.txt
```

### 4. Rust Engine'i Yapılandırın

```bash
# Seçenek A: Rust projesini derleyin (vize projeniz)
cd core_engine
cargo build --release
cp target/release/isu-secops-engine ../core_engine/
cd ..

# Seçenek B: Demo binary (test için)
# Windows:
echo "Fake engine" > core_engine/isu-secops-engine.bat
# Linux/macOS:
echo '#!/bin/sh\necho "[{\"address\":\"127.0.0.1\",\"ports\":[{\"port\":22,\"protocol\":\"tcp\",\"state\":\"open\"}]}]"' \
  > core_engine/isu-secops-engine && chmod +x core_engine/isu-secops-engine
```

### 5. Ortam Değişkenlerini Ayarlayın (Opsiyonel)

```bash
# .env dosyası oluşturun (opsiyonel, varsayılanlar çalışır)
cat > .env << EOF
ISU_LOG_LEVEL=INFO
ISU_LOG_FORMAT=text
ISU_ENGINE_PATH=./core_engine/isu-secops-engine
ISU_REPORTS_DIR=./reports
ISU_SCAN_TIMEOUT=120
ISU_MAX_CONCURRENT_SCANS=5
ISU_REPORT_ORGANIZATION=My Security Team
EOF
```

### 6. Sunucuyu Başlatın

```bash
# Geliştirme modu (otomatik reload):
uvicorn orchestrator.app.main:app --reload --host 0.0.0.0 --port 8000

# Veya doğrudan:
python -m orchestrator.app.main

# Üretim modu (workers ile):
uvicorn orchestrator.app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

API şu adreste hazır olacak:
- **API Docs (Swagger):** http://localhost:8000/api/docs
- **API Docs (ReDoc):** http://localhost:8000/api/redoc
- **Health Check:** http://localhost:8000/api/v1/health

---

## 📡 API Dokümantasyonu

### Endpoint Listesi

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/` | API bilgisi ve endpoint listesi |
| `POST` | `/api/v1/scan` | Yeni tarama başlat |
| `GET` | `/api/v1/scan/{task_id}` | Tarama durumu ve sonuçları |
| `GET` | `/api/v1/scan/{task_id}/report` | Raporu indir (Markdown) |
| `GET` | `/api/v1/reports` | Tüm raporları listele |
| `GET` | `/api/v1/health` | Sistem sağlık kontrolü |

---

### `POST /api/v1/scan` — Tarama Başlat

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24",
    "priority": "high"
  }'
```

**İstek Gövdesi:**

```json
{
  "target": "192.168.1.1",      // IPv4, CIDR veya hostname (zorunlu)
  "extra_args": [],              // Ek engine argümanları (opsiyonel)
  "priority": "normal"           // "low" | "normal" | "high" (opsiyonel)
}
```

**Yanıt (202 Accepted):**

```json
{
  "task_id": "task-a3f9c2b1d840",
  "status": "PENDING",
  "message": "Tarama görevi başarıyla kuyruğa alındı...",
  "target": "192.168.1.1",
  "submitted_at": "2026-06-04T19:15:00.000000+00:00",
  "status_url": "/api/v1/scan/task-a3f9c2b1d840"
}
```

---

### `GET /api/v1/scan/{task_id}` — Durum Sorgula

```bash
curl http://localhost:8000/api/v1/scan/task-a3f9c2b1d840
```

**Yanıt (COMPLETED):**

```json
{
  "task_id": "task-a3f9c2b1d840",
  "status": "COMPLETED",
  "target": "192.168.1.1",
  "submitted_at": "2026-06-04T19:15:00Z",
  "started_at": "2026-06-04T19:15:01Z",
  "completed_at": "2026-06-04T19:15:45Z",
  "duration_seconds": 44.2,
  "hosts_found": 1,
  "total_open_ports": 5,
  "overall_risk": "CRITICAL",
  "report_path": "/path/to/isu_secops_192-168-1-1_20260604_191545.md",
  "error_message": null
}
```

**Durum Değerleri:**

| Durum | Açıklama |
|-------|----------|
| `PENDING` | Kuyruğa alındı, başlamadı |
| `RUNNING` | Aktif olarak devam ediyor |
| `COMPLETED` | Başarıyla tamamlandı |
| `FAILED` | Hata nedeniyle başarısız |
| `TIMEOUT` | Zaman aşımına uğradı |

---

### `GET /api/v1/health` — Sağlık Kontrolü

```bash
curl http://localhost:8000/api/v1/health
```

```json
{
  "status": "healthy",
  "timestamp": "2026-06-04T19:15:00Z",
  "app_name": "ISU-SecOps-Orchestrator",
  "app_version": "1.0.0",
  "engine_available": true,
  "engine_path": "/path/to/isu-secops-engine",
  "engine_version": "isu-secops-engine 1.0.0",
  "active_tasks": 2,
  "configuration": { "..." : "..." }
}
```

---

## 🧪 Testleri Çalıştırma

```bash
# Tüm testleri çalıştır (coverage ile)
pytest tests/ -v --asyncio-mode=auto

# Coverage raporu ile
pytest tests/ -v --cov=orchestrator --cov-report=term-missing

# HTML coverage raporu üret
pytest tests/ --cov=orchestrator --cov-report=html
# → htmlcov/index.html dosyasını tarayıcıda açın

# Belirli test sınıfını çalıştır
pytest tests/ -v -k "TestScanEndpoint"

# Hızlı test (sadece birim testler)
pytest tests/ -v -k "not asyncio"
```

### Test Kategorileri

| Kategori | Test Sayısı | Açıklama |
|----------|-------------|----------|
| Validasyon Testleri | 12+ | sanitize_target, generate_task_id |
| Veri Model Testleri | 15+ | PortInfo, HostInfo, ScanResult |
| Parser Testleri | 10+ | JSON ve metin format ayrıştırma |
| Scanner Mock Testleri | 8+ | subprocess mock ile engine testleri |
| Reporter Birim Testleri | 15+ | Rapor üretimi ve içerik doğrulama |
| API Entegrasyon Testleri | 20+ | httpx.AsyncClient ile endpoint testleri |
| Parametrize Testler | 25+ | Çoklu senaryo kombinasyonları |
| Exception Testleri | 8+ | Hata hiyerarşisi doğrulamaları |

---

## 📊 Üretilen Rapor Örneği

Başarılı bir tarama sonrası `reports/` dizinine aşağıdaki formatta rapor kaydedilir:

```
reports/isu_secops_192-168-1-1_20260604_191545.md
```

Rapor bölümleri:

```markdown
# 🛡️ ISU-SecOps Güvenlik Denetim Raporu

## 📋 1. Yönetici Özeti (Executive Summary)
   - Özet istatistikler tablosu
   - Kritik bulgular listesi
   - Acil eylem gerektiren durumlar

## 🎯 2. Kapsam ve Metodoloji
   - Değerlendirme kapsamı
   - Kullanılan araçlar
   - Sınırlamalar

## 📊 3. Risk Matrisi
   - CRITICAL/HIGH/MEDIUM/LOW dağılımı
   - ASCII ilerleme çubukları
   - CVSS risk tanımları

## 🔍 4. Teknik Bulgular
   - Host başına detaylı tablo
   - Risk seviyeli port analizi
   - OWASP + CWE + CVE referansları

## 🏆 5. OWASP Top 10 Analizi
   - Tespit edilen OWASP kategorileri
   - Referans bağlantıları

## 🔧 6. Sıkılaştırma Önerileri
   - Port bazlı detaylı remediation adımları
   - Genel güvenlik önerileri

## 📌 7. Sonuç ve Tavsiyeler
   - Aciliyet değerlendirmesi
   - Sonraki adımlar planı
```

---

## ⚙️ Konfigürasyon Referansı

Tüm ayarlar `.env` dosyası veya sistem ortam değişkenleri ile override edilebilir:

| Değişken | Varsayılan | Açıklama |
|----------|------------|----------|
| `ISU_LOG_LEVEL` | `INFO` | Log seviyesi: DEBUG, INFO, WARNING, ERROR |
| `ISU_LOG_FORMAT` | `json` | Log formatı: `json` veya `text` |
| `ISU_APP_HOST` | `0.0.0.0` | Sunucu IP adresi |
| `ISU_APP_PORT` | `8000` | Sunucu port numarası |
| `ISU_DEBUG` | `false` | Debug modu |
| `ISU_ENGINE_PATH` | `./core_engine/isu-secops-engine` | Rust binary yolu |
| `ISU_SCAN_TIMEOUT` | `120` | Tarama zaman aşımı (saniye) |
| `ISU_MAX_CONCURRENT_SCANS` | `5` | Eşzamanlı tarama limiti |
| `ISU_REPORTS_DIR` | `./reports` | Rapor çıktı dizini |
| `ISU_REPORT_ORGANIZATION` | `ISU Cyber Security Research Lab` | Rapor kurum adı |

---

## 🔒 Güvenlik Özellikleri

| Özellik | Açıklama |
|---------|----------|
| **Hedef Validasyonu** | IP, CIDR ve hostname format doğrulaması |
| **Komut Enjeksiyonu Koruması** | Extra argümanlarda tehlikeli karakter engeli |
| **Timeout Koruması** | Konfigürasyon tabanlı tarama zaman aşımı |
| **Graceful Process Termination** | Timeout'da SIGTERM → SIGKILL sırası |
| **CORS Kısıtlaması** | Yalnızca izin verilen origin'lere erişim |
| **Yapısal Loglama** | JSON formatında audit trail |

---

## 📚 Teknik Detaylar

### Asenkron Mimari

```python
# BackgroundTasks ile non-blocking tarama
@router.post("/scan")
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanResponse:
    task_id = generate_task_id()
    background_tasks.add_task(_execute_scan_task, task_id, ...)
    return ScanResponse(task_id=task_id, status="PENDING")  # Anında döner
```

### Timeout Korumalı Subprocess

```python
# asyncio.wait_for ile timeout koruması
stdout, stderr = await asyncio.wait_for(
    process.communicate(),
    timeout=settings.scan_timeout,  # Konfigürasyondan
)
```

### Pydantic ile Tip Güvenliği

```python
class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return sanitize_target(v)  # Otomatik validasyon
```

---

## 📄 Lisans

MIT License — Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 👥 Katkıda Bulunanlar

| Rol | Sorumluluk |
|-----|------------|
| Rust Core Engine | Vize Projesi — Port tarama ve servis keşfi |
| Python Orchestrator | Final Projesi — Orkestrasyon, raporlama, API |

---

<div align="center">

**ISU Cyber Security Research Lab** | 2026

*"Security is not a product, but a process."* — Bruce Schneier

</div>
