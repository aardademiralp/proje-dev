<div align="center">
  <a href="https://istinye.edu.tr">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/43/%C4%B0stinye_%C3%9Cniversitesi_logo.svg/360px-%C4%B0stinye_%C3%9Cniversitesi_logo.svg.png" alt="İstinye Üniversitesi" width="180"/>
  </a>

  # ISU-SecOps-Orchestrator

  ![GitHub](https://img.shields.io/badge/GitHub-Private-red?style=flat-square&logo=github)
  ![License](https://img.shields.io/badge/Lisans-MIT-green?style=flat-square)
  ![Dil](https://img.shields.io/badge/Dil-Python%20%26%20Rust-blue?style=flat-square)
  ![Durum](https://img.shields.io/badge/Durum-Tamam%C4%B1na%20Erdirildi-brightgreen?style=flat-square)
  ![Ders](https://img.shields.io/badge/Ders-BGT006-purple?style=flat-square)
</div>

---

### 👨‍🏫 Danışman Bilgileri
| Alan | Bilgi |
|---|---|
| **Ad Soyad** | Keyvan Arasteh |
| **GitHub** | [@keyvanarasteh](https://github.com/keyvanarasteh) |
| **E-posta** | keyvan.arasteh@istinye.edu.tr |
| **LinkedIn** | [keyvanarasteh](https://linkedin.com/in/keyvanarasteh) |
| **Web Sitesi** | [qline.tech](https://qline.tech) |

### 🎓 Öğrenci Bilgileri
| Alan | Bilgi |
|---|---|
| **Ad Soyad** | Aydın Arda Demiralp |
| **Öğrenci No** | 2520****1011 |

### 📖 Ders Bilgileri
| Alan | Bilgi |
|---|---|
| **Ders Adı** | Sızma Testi |
| **Ders Kodu** | BGT006 |
| **Kredi** | 3 AKTS |
| **Ön Koşullar** | Ağ Temelleri, Linux CLI, Python, Rust |
| **Dönem** | 2025-2026 Bahar |

---

## 📖 Proje Hakkında
Bu proje; yüksek yoğunluklu sızma testi, keşif ve ağ güvenliği süreçlerinde port ve zafiyet analizlerini milisaniyeler seviyesinde gerçekleştirmek üzere hibrit mimariyle tasarlanmış bir **Siber Güvenlik Analiz Motoru ve Orkestratörüdür**.

Geleneksel tarayıcıların yüksek yük altında yaşadığı performans darboğazlarını aşmak amacıyla, ağ paket üretimi alt seviye **Rust** motoruna devredilmiş; API ve yönetim süreçleri ise asenkron **Python FastAPI** katmanı ile orkestre edilmiştir.

---

## 🛠️ Teknik Özellikler
*   **🚀 Yüksek Eş Zamanlılık (Concurrency):** Rust ham soket (raw socket) yönetimi ile paket kaçırma oranı sıfıra indirilmiştir.
*   **⚡ Asenkron Mimari:** Uzun süren tarama işlemlerinde API sunucusu kilitlenmez (`async/await` non-blocking I/O).
*   **📊 Gelişmiş Risk Skorlaması:** Bulunan açıklıklar ve port durumları için CVSS bazlı otomatik risk analizi ve sıkılaştırma önerileri üretimi.
*   **🔒 Güvenli Ortam İzolasyonu:** Pydantic BaseSettings tabanlı `.env` ve Docker ekosistemi izolasyonu.

---

## 💻 Mimari Yapı ve İş Akışı

```text
src/
├── core_engine/        # Çok iş parçacıklı (Multi-threaded) Rust Motoru
└── orchestrator/       # FastAPI API Sunucusu, Servisler ve Raporlama
```

1. Kullanıcı API üzerinden `/scans` veya `/scan` uç noktasına tarama isteği gönderir.
2. Orkestratör gelen veriyi Pydantic ile doğrulayıp asenkron subprocess ile Rust binary'sini tetikler.
3. Rust motoru, hedef ağdaki açık kapıları eş zamanlı tarayarak çıktıları yapılandırılmış JSON olarak fırlatır.
4. Python servis katmanı dönen veriyi işler, CVSS risk skorunu hesaplar ve `reports/` dizini altına mühürler.

---

## 🔧 Kurulum ve Çalıştırma

### Sistem Gereksinimleri
*   Rust 1.75+ (rustup)
*   Python 3.10+
*   Docker & Docker Compose (Opsiyonel)

### 1. Yerel Geliştirme Ortamı Kurulumu
```bash
# Bağımlılıkları yükleyin
pip install -r src/orchestrator/requirements.txt

# Rust motorunu derleyin
cd src/core_engine && cargo build --release
```

### 2. Docker Üzerinden Çalıştırma
```bash
# Ortam değişkenlerini yapılandırın
cp .env.example .env

# Konteynerleri başlatın
docker-compose up --build
```

---

## 🧪 Test ve Kalite Kontrolü
Projenin API entegrasyonu ve hata yakalama mekanizmaları otomatik test paketleri ile koruma altındadır:
```bash
# Testleri çalıştırın
pytest src/tests/
```
*   **Rust Kalite Kontrolü:** `cargo clippy` ve `cargo fmt` standartları tüm kaynak kodlarda eksiksize uygulanmıştır.

---

## 🎯 Gerçek Dünya Senaryoları

### Senaryo 1: Hızlı Ağ Keşfi ve Port Analizi
Bir sızma testi esnasında hedef sistemlerin aktif servislerini ve açık kapılarını saptamak için:
```bash
curl -X 'POST' 'http://localhost:8000/api/v1/scan' \
  -H 'Content-Type: application/json' \
  -d '{"target": "192.168.1.1"}'
```

### Senaryo 2: Otomatik Sıkılaştırma Raporu Üretimi
Tarama bittiğinde, sistem zafiyet barındıran portlar için çözüm (remediation) önerilerini otomatik üretir:
```bash
cat reports/scan_report.json | jq '.remediation_suggestions'
```

---

## ⚖️ Yasal Uyarı
Bu araç yalnızca yetkili sistemlerde siber güvenlik eğitimleri ve etik sızma testi faaliyetleri kapsamında kullanılmak üzere geliştirilmiştir.

---

## 📄 Lisans
Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.
