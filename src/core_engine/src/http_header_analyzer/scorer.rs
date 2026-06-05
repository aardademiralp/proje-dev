//! # Puanlama Modülü
//!
//! Güvenlik header'larına göre 0-100 arası puan hesaplar.
//! CORS wildcard kullanımı -10 puan cezası uygular.
use super::analyzer::{CorsInfo, HeaderResult};

/// Güvenlik header'larına ve CORS durumuna göre 0–100 arası puan hesaplar.
///
/// Her güvenlik header'ı eşit ağırlık taşır.
/// CORS wildcard kullanımı 10 puan düşürür.
pub fn calculate_score(headers: &[HeaderResult], cors: &CorsInfo) -> u8 {
    if headers.is_empty() {
        return 0;
    }

    let passed = headers.iter().filter(|h| h.passed).count();
    let total = headers.len();

    // Temel puan: geçen header / toplam header
    let base: f64 = (passed as f64 / total as f64) * 100.0;

    // CORS wildcard cezası
    let penalty: f64 = if cors.risky { 10.0 } else { 0.0 };

    (base - penalty).max(0.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_header_analyzer::analyzer::{CorsInfo, HeaderResult};

    fn make_result(passed: bool) -> HeaderResult {
        HeaderResult {
            name: "test-header".to_string(),
            present: passed,
            value: None,
            note: String::new(),
            passed,
        }
    }

    fn no_cors() -> CorsInfo {
        CorsInfo {
            allow_origin: None,
            allow_methods: None,
            wildcard: false,
            risky: false,
        }
    }

    #[test]
    fn test_all_passed_full_score() {
        let headers = vec![make_result(true); 7];
        let score = calculate_score(&headers, &no_cors());
        assert_eq!(score, 100);
    }

    #[test]
    fn test_none_passed_zero_score() {
        let headers = vec![make_result(false); 7];
        let score = calculate_score(&headers, &no_cors());
        assert_eq!(score, 0);
    }

    #[test]
    fn test_cors_penalty_applied() {
        let headers = vec![make_result(true); 7];
        let risky_cors = CorsInfo {
            allow_origin: Some("*".to_string()),
            allow_methods: None,
            wildcard: true,
            risky: true,
        };
        let score = calculate_score(&headers, &risky_cors);
        assert_eq!(score, 90);
    }

    #[test]
    fn test_empty_headers_zero_score() {
        let score = calculate_score(&[], &no_cors());
        assert_eq!(score, 0);
    }

    #[test]
    fn test_half_passed() {
        let mut headers = vec![make_result(true); 4];
        headers.extend(vec![make_result(false); 4]);
        let score = calculate_score(&headers, &no_cors());
        assert_eq!(score, 50);
    }
}
