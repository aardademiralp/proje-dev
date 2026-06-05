# 📦 Modül Dokümantasyonu (docs/modules/orchestrator_module.md)

Bu belgede, **ISU-SecOps-Orchestrator** backend sisteminin temel modülleri, sınıfları ve işlevleri açıklanmaktadır.

---

## 1. RustEngineWrapper (`orchestrator/app/scanner.py`)
Rust tabanlı tarama motorunun asenkron olarak çağrılmasını, çıktısının okunmasını ve yönetilmesini sağlayan çekirdek modüldür.

### Ana Fonksiyonlar:
*   `run_scan(task_id: str, target: str, extra_args: list[str]) -> ScanResult`: Belirtilen hedefe yönelik asenkron tarama işlemini başlatır.
*   `_execute_with_timeout(...)`: Komutu asenkron süreç olarak çalıştırır ve belirlenen timeout süresi içinde tamamlanmasını garanti eder.
*   `health_check() -> dict`: Rust binary'sinin erişilebilirliğini ve sürümünü doğrular.

---

## 2. VulnerabilityReportGenerator (`orchestrator/app/reporter.py`)
Taramadan elde edilen JSON veya ham metin sonuçlarını okuyarak insan ve makine tarafından okunabilir profesyonel güvenlik denetim raporlarına (Markdown) dönüştüren rapordur.

### Ana Fonksiyonlar:
*   `generate(scan_result: ScanResult) -> Path`: Rapor oluşturma sürecini başlatır ve diske kaydeder.
*   `_render_executive_summary(...)`: Üst düzey özet tabloları ve istatistikleri hazırlar.
*   `_render_risk_matrix(...)`: ASCII tabanlı bulgu dağılım grafiğini oluşturur.
*   `_render_remediation(...)`: Tespit edilen açıklara yönelik çözüm ve sıkılaştırma adımlarını listeler.

---

## 3. FastAPI Web Sunucusu (`orchestrator/app/main.py`)
Dış dünyayla iletişimi kuran, dashboard'u sunan ve REST API uç noktalarını (endpoints) barındıran katmandır.

### API Uç Noktaları:
*   `POST /api/v1/scan`: Yeni bir tarama görevi kuyruğa ekler (BackgroundTasks).
*   `GET /api/v1/scan/{task_id}`: Taramaya ait güncel durumu (PENDING, RUNNING, COMPLETED, FAILED) döner.
*   `GET /api/v1/reports`: Kaydedilmiş tüm Markdown raporlarının listesini döner.
*   `GET /api/v1/health`: Orkestratörün ve tarama motorunun sağlık durumunu sorgular.
