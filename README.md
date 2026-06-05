<div align="center">
  <a href="https://istinye.edu.tr">
    <img src="https://www.istinye.edu.tr/sites/default/files/2018-05/isu-logo.png" alt="İstinye Üniversitesi" width="180"/>
  </a>

  # ISU-SecOps-Engine & Orchestrator

  ![GitHub](https://img.shields.io/badge/GitHub-Private-red?style=flat-square&logo=github)
  ![Dil](https://img.shields.io/badge/Dil-Rust%20%7C%20Python-blue?style=flat-square)
  ![Durum](https://img.shields.io/badge/Durum-Devam%20Ediyor-yellow?style=flat-square)
  ![Ders](https://img.shields.io/badge/Ders-BGT006%20%7C%20BGT208%20%7C%20BGT210-purple?style=flat-square)
</div>

---

### 📋 Danışman Bilgisi
| Ad Soyad | Keyvan Arasteh |
| :--- | :--- |
| **GitHub** | [@keyvanarasteh](https://github.com/keyvanarasteh) |
| **E-posta** | keyvan.arasteh@istinye.edu.tr |
| **LinkedIn** | [keyvanarasteh](https://linkedin.com/in/keyvanarasteh) |
| **Web Sitesi** | [qline.tech](https://qline.tech) |

### 🎓 Öğrenci Bilgisi
| Ad Soyad | Aydın Arda Demiralp |
| :--- | :--- |
| **Öğrenci No** | 2520**1011 |

### 📚 Ders Bilgileri
| Ders Adı | Sızma Testi|
| :--- | :--- |
| **Ders Kodu** | BGT006|
| **Kredi** | 5 AKTS |
| **Ön Koşullar** | Ağ Temelleri, Linux CLI, Python, Rust Giriş |
| **Dönem** | 2025-2026 Bahar |

---

## 📌 İçindekiler Table of Contents
* [🚀 Proje Hakkında](#-proje-hakkında)
* [🛠️ Teknik Özellikler](#️-teknik-özellikler)
* [💻 Mimari Yapı ve İş Akışı](#-mimari-yapı-ve-iş-akışı)
* [🔧 Kurulum ve Çalıştırma](#-kurulum-ve-çalıştırma)
* [🧪 Test ve Kalite Kontrolü](#-test-ve-kalite-kontrolü)
* [🎯 Gerçek Dünya Senaryoları](#-gerçek-dünya-senaryoları)
* [⚖️ Yasal Uyarı](#️-yasal-uyarı)

---

## 🚀 Proje Hakkında
Bu proje; yüksek yoğunluklu sızma testi, keşif ve ağ güvenliği süreçlerinde port ve zafiyet analizlerini milisaniyeler seviyesinde gerçekleştirmek üzere hibrit mimariyle tasarlanmış bir **Siber Güvenlik Analiz Motoru ve Orkestratörüdür**. 

Geleneksel tarayıcıların yüksek yük altında yaşadığı performans darboğazlarını aşmak amacıyla, ağ paket üretimi alt seviye **Rust** motoruna devredilmiş; API ve yönetim süreçleri ise asenkron **Python FastAPI** katmanı ile orkestre edilmiştir.

---

## 🛠️ Teknik Özellikler
* **Yüksek Eş Zamanlılık (Concurrency):** Rust ham soket (raw socket) yönetimi ile paket kaçırma oranı sıfıra indirilmiştir.
* **Asenkron Mimari:** Uzun süren tarama işlemlerinde API sunucusu kilitlenmez (`async/await` non-blocking I/O).
* **Gelişmiş Risk Skorlaması:** Bulunan açıklıklar ve port durumları için CVSS bazlı otomatik risk analizi ve sıkılaştırma önerileri üretimi.
* **Güvenli Ortam İzolasyonu:** Pydantic BaseSettings tabanlı `.env` ve Docker ekosistemi izolasyonu.
* **Otomatik Raporlama:** Gerçekleşen taramaların bulguları anlık olarak `reports/` dizini altında JSON formatında arşivlenir.

---

## 💻 Mimari Yapı ve İş Akışı

```text
src/
├── core_engine/          # Çok iş parçacıklı (Multi-threaded) Rust Motoru
└── orchestrator/         # FastAPI API Sunucusu, Servisler ve Raporlama
```

Kullanıcı API üzerinden /scans uç noktasına tarama isteği gönderir.

Orkestratör gelen veriyi Pydantic ile doğrulayıp asenkron subprocess ile Rust binary'sini tetikler.

Rust motoru, hedef ağdaki açık kapıları eş zamanlı tarayarak çıktıları yapılandırılmış JSON olarak fırlatır.

Python servis katmanı dönen veriyi işler, CVSS risk skorunu basar ve reports/ altına mühürler.

🔧 Kurulum ve Çalıştırma
Gereksinimler
Rust 1.75+ (rustup)

Python 3.10+

Docker & Docker Compose (Opsiyonel)

Yerel Geliştirme Ortamı
pip install -r src/orchestrator/requirements.txt
cd src/core_engine && cargo build --release

Docker Üzerinden Çalıştırma
cp .env.example .env
docker-compose up --build

🧪 Test ve Kalite Kontrolü
Projenin API entegrasyonu ve hata yakalama mekanizmaları otomatik test paketleri ile koruma altındadır.
pytest src/tests/
Rust Kalite Kontrolü: cargo clippy ve cargo fmt standartları tüm kaynak kodlarda eksiksiz uygulanmıştır.

🎯 Gerçek Dünya Senaryoları
Senaryo 1: Hızlı Ağ Keşfi ve Port Analizi
Bir sızma testi esnasında hedef sistemlerin aktif servislerini ve açık kapılarını saptamak için:
curl -X 'POST' 'http://localhost:8000/api/v1/scans' -H 'Content-Type: application/json' -d '{"target": "192.168.1.1"}'
Senaryo 2: Otomatik Sıkılaştırma Raporu Üretimi
Tarama bittiğinde, sistem zafiyet barındıran portlar için remediation (çözüm) önerilerini otomatik üretir:
cat reports/scan_report.json | jq '.remediation_suggestions'

⚖️ Yasal Uyarı
Bu araç yalnızca yetkili sistemlerde siber güvenlik eğitimleri ve etik sızma testi faaliyetleri kapsamında kullanılmak üzere geliştirilmiştir.
