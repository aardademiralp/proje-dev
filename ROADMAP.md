# 🗺️ Proje Yol Haritası (ROADMAP)

Keyvan Arasteh hocamızın felsefesi doğrultusunda: *"Önce anla, sonra kodla."* Bu belgede projenin sıfırdan teslim anına kadar olan tüm araştırma, geliştirme ve test fazları adım adım dökümante edilmiştir.

---

## 🧭 Faz 0: Yazmadan Önce Anla
- [x] Sızma testi süreçlerinde port ve ağ taramalarının mimari gereksinimlerinin analiz edilmesi.
- [x] Python (FastAPI) orkestrasyon katmanı ile Rust (Core) tarama motoru arasındaki asenkron veri akışının ve IPC (Inter-Process Communication) mekanizmalarının planlanması.
- [x] Tarama çıktılarının yapılandırılmış veri formatlarına (JSON/Rapor) dönüştürülme şemasının belirlenmesi.

## 🔬 Faz 1: Araştırma ve Keşif
- [x] Rust mimarisinde ham soketler (raw sockets) ve asenkron ağ kütüphanelerinin incelenmesi (Detaylar için bkz: `docs/research/`).
- [x] Çıkmaz sokak analizi: Python tabanlı tarayıcıların yüksek yük altında yaşadığı GIL (Global Interpreter Lock) engellerinin ve performans darboğazlarının saptanması.
- [x] Çözümleme: Çok iş parçacıklı (Multi-threaded) Rust motorunun entegrasyonu ile bu engelin aşılması.

## ⚙️ Faz 2: Ortam Kurulumu
- [x] Rust derleme araçları (`cargo`) ve Python sanal ortamlarının (`poetry` / `venv`) Kali Linux üzerinde ayağa kaldırılması.
- [x] `.env.example` şablonunun hazırlanması ve ortam değişkenlerinin güvenli şekilde yapılandırılması.
- [x] Bağımlılıkların (`FastAPI`, `Uvicorn`, `Pytest`) tanımlanarak izole geliştirme ortamının mühürlenmesi.

## 🛠️ Faz 3: Uygulama (Modül Geliştirme)
### Modül 1: Rust Core Engine
- [x] Adım 1: Ham ağ paketleri üretimi ve soket yönetimi altyapısının kurulması.
- [x] Adım 2: Çok iş parçacıklı port tarama algoritmasının optimize edilmesi.
- [x] Adım 3: Sonuçların orkestratörün okuyabileceği standart JSON formatına serialize edilmesi.

### Modül 2: Python FastAPI Orchestrator
- [x] Adım 1: Uygulama iskeletinin ve APIRouter yapısının kurgulanması.
- [x] Adım 2: Rust motorunu alt süreç (subprocess) olarak tetikleyen servis katmanının yazılması.
- [x] Adım 3: `ports/` ve `scans/` endpoint'lerinin güvenli giriş doğrulamalarıyla (Pydantic) açılması.

## 🧪 Faz 4: Test ve Raporlama
- [x] `pytest` kütüphanesi kullanılarak API uç noktalarının entegrasyon testlerinin tamamlanması (`tests/test_orchestrator.py`).
- [x] Sahte tarama senaryoları ile hata yakalama mekanizmalarının sınanması.
- [x] Çıktıların otomatik olarak `reports/` dizinine yazılmasının doğrulanması.

## 📦 Faz 5: Teslim Kontrol Listesi
- [x] Projenin akademik standartlara uygun olarak `src/` ve `docs/` mimarisine taşınması.
- [x] `README.md` dosyasının İstinye Üniversitesi şablonuna göre güncellenmesi.
- [ ] `Dockerfile` ve `docker-compose.yml` yapılandırmalarının tamamlanması.
- [ ] Danışman hocamız `@keyvanarasteh`'in reponun ayarlarına işbirlikçi (Collaborator) olarak eklenmesi.
