# 🗺️ ISU-SecOps-Orchestrator Yol Haritası (ROADMAP.md)

Bu dosya, İstinye Üniversitesi Siber Güvenlik Bölümü Bitirme Projesi standartlarına uygun olarak, projenin araştırma, kurulum, uygulama ve test aşamalarını belgelemektedir.

---

## 🚀 Faz 0: Yazmadan Önce Anla
Projenin temel amacı, yüksek performanslı bir ağ keşif motorunu (Rust Core Engine) ölçeklenebilir ve yönetilebilir bir orkestrasyon katmanıyla (Python/FastAPI) birleştirerek uçtan uca otomatik bir güvenlik tarama ve raporlama hattı (SOAR) oluşturmaktır.

### Problem Tanımı ve Gereksinimler:
*   **Asenkron Çalışma:** Tarama işlemlerinin web sunucusunun ana hattını bloklamaması gerekir.
*   **Hata Toleransı:** Tarama motoru kilitlendiğinde veya zaman aşımına uğradığında sistemin gracefully sonlanması gerekir.
*   **Bulgu Sınıflandırması:** Tespit edilen açık portların rastgele listelenmesi yerine, CVSS v3.1 tabanlı risk puanlaması ve OWASP Top 10 standardına göre eşlenmesi gerekir.
*   **Kullanıcı Arayüzü:** API tetiklemelerinin ve sonuçların gerçek zamanlı takip edilebileceği modern bir dashboard ihtiyacı.

---

## 🔬 Faz 1: Araştırma ve Keşif
*Detaylı araştırma notları [docs/research/](docs/research/research_notes.md) altında bulunmaktadır.*

*   **Rust Subprocess Entegrasyonu:** Python'daki `asyncio.subprocess` modülü incelendi. Süreç yönetiminde timeout kontrolü ve stderr tamponlarının kilitlenmesini önlemek için `communicate()` kullanımı araştırıldı.
*   **Ayrıştırma (Parsing) Stratejileri:** Taramadan dönen verinin hem ham metin (structured text) hem de JSON formatında olabilmesi nedeniyle otomatik format algılama yapısı araştırıldı.
*   **Güvenlik Standartları:** Açık portların OWASP Top 10 (2021) kategorileri (ör. A05:2021 - Security Misconfiguration) ve ilgili CWE tanımlarıyla (ör. CWE-319) eşleştirilmesi için veri yapıları oluşturuldu.

---

## ⚙️ Faz 2: Ortam Kurulumu
1.  **Python Sanal Ortamı:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2.  **Bağımlılıkların Yüklenmesi:**
    ```bash
    pip install -e .[dev]
    ```
3.  **Rust Core Engine Derlenmesi (Vize Modülü):**
    ```bash
    cd core_engine
    cargo build --release
    ```
4.  **Ortam Değişkenlerinin Yapılandırılması:**
    *   `.env.example` dosyası `.env` olarak kopyalandı ve `ISU_ENGINE_PATH` değişkeni ayarlandı.

---

## 🛠️ Faz 3: Uygulama (Modül Adımları)

### Modül 1: RustEngineWrapper (Asenkron Tarayıcı Katmanı)
1.  `_validate_engine()` ile Rust binary'sinin varlığı ve çalıştırma izinleri denetlenir.
2.  `_build_command()` ile hedef IP/domain adresine göre komut token'ları üretilir.
3.  `asyncio.create_subprocess_exec` ile süreç asenkron başlatılır.
4.  `asyncio.wait_for` ile `scan_timeout` kontrolü uygulanır.
5.  Dönen stderr ve exit code denetlenerek özel istisnalar (`EngineCrashError`, `EngineTimeoutError`) fırlatılır.

### Modül 2: VulnerabilityReportGenerator (Rapor Motoru)
1.  `_compute_summary` metodu ile CVSS-benzeri risk sayıları hesaplanır.
2.  `_render_header` ile TLP:RED gizlilik etiketli profesyonel rapor başlığı oluşturulur.
3.  `_render_executive_summary` ile yönetici özeti ve istatistikleri üretilir.
4.  `_render_risk_matrix` ile bulguların ASCII bar-chart dağılım grafiği çizilir.
5.  `_render_technical_findings` ile port detayları, CWE linkleri ve CVE örnekleri yerleştirilir.
6.  `_render_remediation` ile her açık porta özel sıkılaştırma ve çözüm önerileri basılır.

### Modül 3: Web Dashboard & API (FastAPI)
1.  `APIRouter` ile `/api/v1/scan`, `/api/v1/reports` ve `/api/v1/health` uç noktaları kurulur.
2.  FastAPI `BackgroundTasks` kullanılarak taramalar arka planda asenkron yürütülür.
3.  Web Dashboard modern Neon/SecOps temasıyla, dinamik grafiklerle ve tarama başlatma formuyla kodlanır.

---

## 🧪 Faz 4: Test ve Raporlama
*   **Test Kütüphanesi:** `pytest` ve `pytest-asyncio` kullanılarak tüm asenkron süreçler izole edildi.
*   **Mock Yapısı:** Rust binary'si ve disk yazma işlemleri `unittest.mock` ile simüle edildi.
*   **Kapsam Oranı (Coverage):** Test kapsamının `%95+` seviyesinde olması sağlandı.
*   **Çalıştırma:**
    ```bash
    pytest src/tests/ -v
    ```

---

## 📋 Faz 5: Teslim Kontrol Listesi
*   [x] `README.md` dosyası İstinye Üniversitesi standart şablonuna göre güncellendi.
*   [x] `ROADMAP.md` dosyası faz aşamalarıyla tamamlandı.
*   [x] `docs/research/research_notes.md` dosyası oluşturuldu.
*   [x] `Dockerfile` ve `docker-compose.yml` dosyaları eklendi.
*   [x] `.env.example` dosyası repoda mevcut.
*   [x] Danışman hoca (`keyvanarasteh`) repoya collaborator olarak davet edildi.
*   [x] `pytest` testlerinin tamamı (132 test) başarıyla geçiyor.
