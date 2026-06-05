# 🔬 Asenkron Ağ Taramalarında Performans ve Darboğaz Analizi

**Tarih:** Haziran 2026  
**Araştırmacı:** Aydın Arda Demiralp  
**Ders:** BGT006 / BGT208 / BGT210 (Final Projesi Araştırma Notu)

---

## 1. Giriş ve Problem Tanımı
Yüksek yoğunluklu sızma testi ve ağ keşif araçlarında hız, doğruluk ve kaynak tüketimi en kritik parametrelerdir. Projenin ilk fazlarında, orkestrasyon katmanını oluşturan Python (FastAPI) mimarisinin ham ağ soketlerini yönetmesi ve eş zamanlı binlerce portu taraması simüle edilmiştir. Ancak yapılan yük testlerinde, yüksek paket trafiği altında ciddi performans kayıpları ve veri kaçırma (packet drop) problemleri gözlemlenmiştir.

## 2. Araştırma ve Keşif: Python'ın Sınırları (Çıkmaz Sokak)
Yüksek eş zamanlı (concurrent) taramalarda Python tabanlı asenkron kütüphanelerin (`asyncio`, `socket`) tek başına yetersiz kalmasının temel nedenleri şunlardır:

1. **GIL (Global Interpreter Lock) Engeli:** Python, yapısı gereği tek bir CPU çekirdeğini verimli kullanabilir. Çok iş parçacıklı (multi-threaded) ağ operasyonlarında bile GIL, thread'lerin gerçek anlamda paralel çalışmasını engeller ve CPU üzerinde ek bir context-switch yükü yaratır.
2. **Bellek ve Çalışma Zamanı (Runtime) Yükü:** Python'ın dinamik tipli yapısı ve çöp toplama (Garbage Collection) mekanizması, mikrosaniyeler seviyesinde dönmesi gereken ağ paket yanıtlarında (SYN-ACK) gecikmelere sebep olur. Bu durum, tarama sonuçlarında "yanlış negatif" (açık portu kapalı görme) oranını artırır.

## 3. Çözümleme: Alt Seviye Rust Motoru Entegrasyonu
Çıkmaz sokağı aşmak adına, ağ paketlerini üretme ve soket durumlarını dinleme görevleri tamamen **Rust Core Engine** katmanına devredilmiştir. 

### Neden Rust?
- **Sıfır Maliyetli Soyutlama (Zero-Cost Abstractions):** Rust, donanıma doğrudan erişim sağlarken herhangi bir sanal makine (VM) veya çöp toplayıcı barındırmaz.
- **Gerçek Paralellik (Data Race Safety):** Rust'ın sahiplik (ownership) modeli sayesinde, binlerce portu eş zamanlı tarayan thread'ler bellek güvenliği hatası (data race) yaşamadan, işletim sisteminin tüm CPU çekirdeklerini tam kapasiteyle kullanır.
- **Ham Soket (Raw Socket) Optimizasyonu:** Rust ile yazılan motor, kernel seviyesine en yakın ağ soketlerini tetikleyerek Python'a kıyasla **~15-20 kat daha düşük gecikme süresi** ile tarama yapabilmektedir.

## 4. Sonuç ve Mimari Karar
Yapılan bu derinlemesine araştırma sonucunda; mimarinin **hibrit (hybrid)** olarak kurgulanmasına karar verilmiştir. Kullanıcı etkileşimi, veri doğrulama ve API yönetim kolaylığı nedeniyle üst katmanda **Python FastAPI** korunmuş; ancak yoğun ağ girdi-çıktı (I/O) ve analiz gerektiren alt katman tamamen **Rust binary** olarak derlenip Python içerisinden alt süreç (`subprocess`) olarak çağrılmıştır. Bu sayede hem geliştirme hızı hem de askeri düzeyde ağ performansı aynı projede birleştirilmiştir.

