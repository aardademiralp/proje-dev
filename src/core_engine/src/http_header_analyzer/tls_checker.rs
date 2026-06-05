//! # TLS Kontrol Modülü
//!
//! Hedef sunucunun TLS/SSL sertifika bilgilerini kontrol eder.

use reqwest::Client;

/// TLS analiz sonucunu temsil eder.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TlsReport {
    /// Bağlantı başarılı mı?
    pub connected: bool,
    /// HTTPS kullanılıyor mu?
    pub https: bool,
    /// Sertifika geçerli mi?
    pub cert_valid: bool,
    /// Genel TLS notu
    pub note: String,
}

/// Verilen URL için TLS/SSL kontrolü yapar.
pub async fn check_tls(url: &str) -> TlsReport {
    let https = url.starts_with("https://");

    if !https {
        return TlsReport {
            connected: false,
            https: false,
            cert_valid: false,
            note: "HTTPS kullanilmiyor — baglanti sifrelenmemis".to_string(),
        };
    }

    let client = Client::builder()
        .danger_accept_invalid_certs(false)
        .timeout(std::time::Duration::from_secs(10))
        .build();

    match client {
        Ok(c) => match c.get(url).send().await {
            Ok(_) => TlsReport {
                connected: true,
                https: true,
                cert_valid: true,
                note: "TLS baglantisi basarili, sertifika gecerli".to_string(),
            },
            Err(e) if e.is_connect() => TlsReport {
                connected: false,
                https: true,
                cert_valid: false,
                note: "Sertifika gecersiz veya suresi dolmus".to_string(),
            },
            Err(_) => TlsReport {
                connected: false,
                https: true,
                cert_valid: false,
                note: "TLS baglantisi basarisiz".to_string(),
            },
        },
        Err(_) => TlsReport {
            connected: false,
            https: true,
            cert_valid: false,
            note: "HTTP istemcisi olusturulamadi".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_url_not_secure() {
        let report = check_tls("http://example.com").await;
        assert!(!report.https);
        assert!(!report.cert_valid);
    }

    #[tokio::test]
    async fn test_https_url_valid() {
        let report = check_tls("https://example.com").await;
        assert!(report.https);
    }
}
