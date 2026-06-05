# 📦 Modül Mimari Kılavuzu

Bu belge, proje kapsamındaki temel modüllerin görev tanımlarını ve birbirleriyle olan entegrasyon yapısını açıklamaktadır.

## 1. Rust Core Engine Modülü (`src/core_engine`)
- **Görevi:** Ağ paketlerinin üretilmesi, ham soket (raw socket) yönetimi ve yüksek hızlı, eş zamanlı port taramalarının gerçekleştirilmesi.
- **Çıktı Biçimi:** Tarama sonuçlarını standartlaştırılmış, parse edilmeye hazır bir JSON dizesi olarak standart çıktı (stdout) üzerinden iletir.

## 2. Python FastAPI Orchestrator Modülü (`src/orchestrator`)
- **Görevi:** Kullanıcı isteklerini doğrulama (Pydantic), alt süreç yönetimi (Subprocess) ve raporlama katmanlarının yönetilmesi.
- **İş Akışı:** Gelen API tarama isteklerini asenkron (`async/await`) olarak karşılar, Rust binary dosyasını tetikler, dönen veriyi işleyerek `reports/` dizinine kurumsal bir rapora dönüştürür.
