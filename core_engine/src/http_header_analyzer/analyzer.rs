//! # Analyzer Modülü
//!
//! HTTP isteği atarak güvenlik header'larını analiz eder.
//! 10 kritik header kontrolü ve CORS analizi yapar.
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

use super::scorer::calculate_score;

/// Tek bir header'ın analiz sonucunu temsil eder.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderResult {
    /// Header'ın adı
    pub name: String,
    /// Header mevcut mu?
    pub present: bool,
    /// Header'ın değeri (varsa)
    pub value: Option<String>,
    /// Güvenlik açısından değerlendirme notu
    pub note: String,
    /// Bu header geçti mi / kritik mi?
    pub passed: bool,
}

/// Tüm analiz raporunu temsil eder.
#[derive(Debug, Serialize, Deserialize)]
pub struct HeaderReport {
    /// Analiz edilen URL
    pub url: String,
    /// HTTP durum kodu
    pub status_code: u16,
    /// Sunucu bilgisi (varsa)
    pub server: Option<String>,
    /// Her header için analiz sonucu
    pub headers: Vec<HeaderResult>,
    /// CORS politikası özeti
    pub cors: CorsInfo,
    /// Genel güvenlik puanı (0–100)
    pub score: u8,
    /// Puan harfi (A–F)
    pub grade: String,
}

/// CORS başlık bilgilerini tutar.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorsInfo {
    /// Access-Control-Allow-Origin değeri
    pub allow_origin: Option<String>,
    /// Access-Control-Allow-Methods değeri
    pub allow_methods: Option<String>,
    /// Wildcard (*) kullanılıyor mu?
    pub wildcard: bool,
    /// CORS riski var mı?
    pub risky: bool,
}

/// Güvenlik açısından kontrol edilecek header listesi.
const SECURITY_HEADERS: &[(&str, &str, &str)] = &[
    (
        "strict-transport-security",
        "HSTS eksik — HTTP downgrade saldırılarına açık",
        "HSTS mevcut ✓",
    ),
    (
        "content-security-policy",
        "CSP eksik — XSS saldırılarına açık",
        "CSP mevcut ✓",
    ),
    (
        "x-frame-options",
        "X-Frame-Options eksik — Clickjacking riski",
        "X-Frame-Options mevcut ✓",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options eksik — MIME sniffing riski",
        "X-Content-Type-Options mevcut ✓",
    ),
    (
        "referrer-policy",
        "Referrer-Policy eksik — veri sızıntısı riski",
        "Referrer-Policy mevcut ✓",
    ),
    (
        "permissions-policy",
        "Permissions-Policy eksik — tarayıcı API izinleri kontrolsüz",
        "Permissions-Policy mevcut ✓",
    ),
    (
        "x-xss-protection",
        "X-XSS-Protection eksik (eski tarayıcılar için önerilir)",
        "X-XSS-Protection mevcut ✓",
    ),
    (
        "cross-origin-opener-policy",
        "COOP eksik — cross-origin izolasyon yok",
        "COOP mevcut ✓",
    ),
    (
        "cross-origin-resource-policy",
        "CORP eksik — kaynak izolasyon yok",
        "CORP mevcut ✓",
    ),
    (
        "cross-origin-embedder-policy",
        "COEP eksik — embedding izolasyon yok",
        "COEP mevcut ✓",
    ),
];

/// Verilen URL'e istek atarak HTTP güvenlik header'larını analiz eder.
///
/// # Parametreler
/// - `url`: Analiz edilecek hedef URL
///
/// # Döndürür
/// Başarılı olursa `HeaderReport`, hata durumunda `String` hata mesajı.
///
/// # Örnek
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use pentester::http_header_analyzer::analyze_headers;
/// let report = analyze_headers("https://example.com").await.unwrap();
/// println!("Puan: {}", report.grade);
/// # }
/// ```
pub async fn analyze_headers(url: &str) -> Result<HeaderReport, String> {
    // URL doğrulama
    Url::parse(url).map_err(|e| format!("Geçersiz URL: {e}"))?;

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP istemcisi oluşturulamadı: {e}"))?;

    let response = client
        .get(url)
        .header("User-Agent", "ISU-SecOps-Engine/0.1")
        .send()
        .await
        .map_err(|e| format!("İstek başarısız: {e}"))?;

    let status_code = response.status().as_u16();

    // Header'ları HashMap'e al
    let raw_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let server = raw_headers.get("server").cloned();

    // Güvenlik header'larını analiz et
    let headers: Vec<HeaderResult> = SECURITY_HEADERS
        .iter()
        .map(|(name, fail_note, pass_note)| {
            let value = raw_headers.get(*name).cloned();
            let present = value.is_some();
            HeaderResult {
                name: name.to_string(),
                present,
                value: value.clone(),
                note: if present {
                    pass_note.to_string()
                } else {
                    fail_note.to_string()
                },
                passed: present,
            }
        })
        .collect();

    // CORS analizi
    let cors = analyze_cors(&raw_headers);

    // Puan hesapla
    let score = calculate_score(&headers, &cors);
    let grade = score_to_grade(score);

    Ok(HeaderReport {
        url: url.to_string(),
        status_code,
        server,
        headers,
        cors,
        score,
        grade,
    })
}

/// CORS header'larını analiz eder ve risk değerlendirmesi yapar.
fn analyze_cors(headers: &HashMap<String, String>) -> CorsInfo {
    let allow_origin = headers.get("access-control-allow-origin").cloned();
    let allow_methods = headers.get("access-control-allow-methods").cloned();
    let wildcard = allow_origin.as_deref() == Some("*");
    let risky = wildcard;

    CorsInfo {
        allow_origin,
        allow_methods,
        wildcard,
        risky,
    }
}

/// Sayısal puanı harf notuna dönüştürür.
///
/// | Puan | Not |
/// |------|-----|
/// | 90+  | A   |
/// | 75+  | B   |
/// | 60+  | C   |
/// | 45+  | D   |
/// | <45  | F   |
pub fn score_to_grade(score: u8) -> String {
    match score {
        90..=100 => "A".to_string(),
        75..=89 => "B".to_string(),
        60..=74 => "C".to_string(),
        45..=59 => "D".to_string(),
        _ => "F".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_to_grade_a() {
        assert_eq!(score_to_grade(95), "A");
        assert_eq!(score_to_grade(90), "A");
    }

    #[test]
    fn test_score_to_grade_b() {
        assert_eq!(score_to_grade(80), "B");
        assert_eq!(score_to_grade(75), "B");
    }

    #[test]
    fn test_score_to_grade_c() {
        assert_eq!(score_to_grade(60), "C");
        assert_eq!(score_to_grade(70), "C");
    }

    #[test]
    fn test_score_to_grade_f() {
        assert_eq!(score_to_grade(0), "F");
        assert_eq!(score_to_grade(44), "F");
    }

    #[test]
    fn test_cors_wildcard_is_risky() {
        let mut headers = HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        let cors = analyze_cors(&headers);
        assert!(cors.wildcard);
        assert!(cors.risky);
    }

    #[test]
    fn test_cors_specific_origin_not_risky() {
        let mut headers = HashMap::new();
        headers.insert(
            "access-control-allow-origin".to_string(),
            "https://trusted.com".to_string(),
        );
        let cors = analyze_cors(&headers);
        assert!(!cors.wildcard);
        assert!(!cors.risky);
    }

    #[test]
    fn test_cors_missing_not_risky() {
        let headers = HashMap::new();
        let cors = analyze_cors(&headers);
        assert!(!cors.wildcard);
        assert!(!cors.risky);
    }

    #[test]
    fn test_invalid_url_returns_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(analyze_headers("not-a-url"));
        assert!(result.is_err());
    }
}
