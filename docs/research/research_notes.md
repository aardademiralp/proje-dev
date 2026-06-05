# 🔬 Araştırma ve Geliştirme Notları (docs/research/research_notes.md)

Bu belgede, **ISU-SecOps-Orchestrator** projesinin geliştirilmesi aşamasında yapılan teknik araştırmalar, karşılaşılan mimari zorluklar, çıkmaz sokaklar ve çözüm yaklaşımları detaylandırılmaktadır.

---

## 1. Asenkron Alt Süreç (Subprocess) Yönetimi ve Kilitlenme (Deadlock) Problemi
Rust ile yazılmış tarama motorunun asenkron çağrılması için Python `asyncio` kütüphanesi tercih edilmiştir. Geliştirme sürecinde karşılaşılan en büyük zorluk, alt sürecin ürettiği büyük çıktıların (özellikle geniş IP aralıklarında) stderr ve stdout tamponlarını (buffer) doldurarak işletim sistemi düzeyinde kilitlenmeye (deadlock) yol açmasıdır.

### Çıkmaz Sokak:
İlk başta `asyncio.create_subprocess_exec` çağrıldıktan sonra `process.wait()` kullanılmış ve çıktılar doğrudan `.stdout.read()` ile okunmaya çalışılmıştır. Ancak işletim sistemi tampon limitine ulaştığında Rust binary'si yazmayı durdurmuş ve süreç sonsuza kadar askıda kalmıştır.

### Çözüm:
`process.communicate()` yöntemine geçiş yapılmıştır. Bu yöntem arka planda okuma işlemlerini işletim sistemi tamponlarını şişirmeden asenkron olarak yönetir ve kilitlenmeleri tamamen engeller. Ayrıca `asyncio.wait_for` ile sarmalanarak `scan_timeout` süresi dolduğunda sürecin `process.terminate()` ve ardından `process.kill()` ile temizlenmesi garanti altına alınmıştır.

---

## 2. Port ve Servis Bulgularının OWASP Top 10 ile Eşleştirilmesi
Açık port tespiti tek başına bir anlam ifade etmediği için bu bulguları web uygulama güvenliği standartlarıyla ilişkilendirmek araştırılmıştır.

### Eşleştirme Tablosu:
Geliştirilen eşleştirme matrisinde her kritik port, 2021 OWASP Top 10 standartlarına göre gruplandırılmıştır:
*   **Port 21 (FTP) & Port 23 (Telnet):** Şifrelenmemiş veri iletimi nedeniyle `A05:2021 — Security Misconfiguration` ve `CWE-319 (Cleartext Transmission of Sensitive Information)` ile eşlenmiştir.
*   **Port 22 (SSH):** Güvenli olsa da yanlış yapılandırma veya zayıf parolalara açık olabileceğinden `A07:2021 — Identification and Authentication Failures` ile eşlenmiştir.
*   **Port 80 (HTTP):** SSL/TLS olmaması nedeniyle `A02:2021 — Cryptographic Failures` kategorisine atanmıştır.
*   **Port 445 (SMB) & Port 3389 (RDP):** İnternete açık olmaması gereken kritik servisler olarak `A05:2021` ile eşleştirilmiştir.

---

## 3. CVSS Tabanlı Dinamik Risk Puanlaması
Taramalardan elde edilen verilerin otomatik olarak risk düzeyine (Critical, High, Medium, Low) atanması için basit ama etkili bir kural motoru tasarlanmıştır.

*   **Critical (Kritik):** Doğrudan istismar edilebilen ve RCE (Remote Code Execution) riski barındıran servis portları (SMB-445, RDP-3389, Telnet-23, FTP-21).
*   **High (Yüksek):** Yetkisiz veritabanı erişimi veya bilgi ifşası riski barındıran portlar (Redis-6379, MongoDB-27017, Postgres-5432, MySQL-3306).
*   **Medium (Orta):** Diğer standart servisler ve uygulama katmanı portları.
*   **Low (Düşük):** Güvenli ve şifrelenmiş protokoller kullanan portlar (HTTPS-443, LDAPS-636).
