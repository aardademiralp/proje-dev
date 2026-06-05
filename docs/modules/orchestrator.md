# Orchestrator Modülü

Python/FastAPI tabanlı API ve yönetim katmanı.

## Özellikler
- Asenkron tarama yönetimi (asyncio)
- CVSS v3.1 tabanlı risk skorlaması
- Otomatik JSON rapor üretimi
- REST API uç noktaları

## API Uç Noktaları
| Uç Nokta | Metod | Açıklama |
|---|---|---|
| `/api/v1/scans` | POST | Yeni tarama başlat |
| `/api/v1/reports` | GET | Raporları listele |
| `/api/v1/health` | GET | Sistem durumu |
