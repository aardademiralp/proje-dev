//! # Yazdırma Modülü
//!
//! Terminal çıktısını renkli olarak yazdırır.
//! Geçen header'lar yeşil, eksik olanlar kırmızı gösterilir.
use colored::Colorize;

use super::analyzer::HeaderReport;

/// Terminal raporunu renkli olarak yazdırır.
///
/// Geçen header'lar yeşil, eksik olanlar kırmızı gösterilir.
/// Puan harfi rengine göre renklendirilir (A=yeşil, F=kırmızı).
pub fn print_report(report: &HeaderReport) {
    println!("{}", "═══════════════════════════════════════════".cyan());
    println!("{}", "🛡  ISU-SecOps-Engine — HTTP Header Analyzer".bold());
    println!("{}", "═══════════════════════════════════════════".cyan());

    println!("🌐 URL         : {}", report.url.yellow());
    println!(
        "📡 Durum Kodu  : {}",
        format!("{}", report.status_code).cyan()
    );

    if let Some(ref server) = report.server {
        println!("🖥  Sunucu      : {}", server.yellow());
    } else {
        println!("🖥  Sunucu      : {}", "Belirtilmemiş".dimmed());
    }

    println!();
    println!("{}", "── Güvenlik Header'ları ──────────────────".dimmed());

    for h in &report.headers {
        let icon = if h.passed { "✅" } else { "❌" };
        let note = if h.passed {
            h.note.green().to_string()
        } else {
            h.note.red().to_string()
        };

        println!("  {}  {:<35} {}", icon, h.name.bold(), note);

        if let Some(ref val) = h.value {
            let truncated = if val.len() > 80 {
                format!("{}…", &val[..80])
            } else {
                val.clone()
            };
            println!("      └─ {}", truncated.dimmed());
        }
    }

    println!();
    println!("{}", "── CORS Analizi ──────────────────────────".dimmed());

    match &report.cors.allow_origin {
        Some(origin) => {
            if report.cors.wildcard {
                println!(
                    "  ⚠️  Access-Control-Allow-Origin: {} {}",
                    origin.red().bold(),
                    "(Wildcard — Riskli!)".red()
                );
            } else {
                println!("  ✅ Access-Control-Allow-Origin: {}", origin.green());
            }
        }
        None => println!("  ℹ️  CORS header'ı yok (API değil, normal)"),
    }

    if let Some(ref methods) = report.cors.allow_methods {
        println!("     Access-Control-Allow-Methods: {}", methods.cyan());
    }

    println!();
    println!("{}", "── Güvenlik Puanı ────────────────────────".dimmed());

    let grade_colored = match report.grade.as_str() {
        "A" => report.grade.green().bold().to_string(),
        "B" => report.grade.cyan().bold().to_string(),
        "C" => report.grade.yellow().bold().to_string(),
        "D" => report.grade.truecolor(255, 165, 0).bold().to_string(),
        _ => report.grade.red().bold().to_string(),
    };

    println!("  📊 Puan  : {} / 100", report.score.to_string().bold());
    println!("  🏆 Not   : {}", grade_colored);

    println!();
    println!("{}", "═══════════════════════════════════════════".cyan());

    let passed = report.headers.iter().filter(|h| h.passed).count();
    let total = report.headers.len();
    println!(
        "  {} / {} header geçti",
        passed.to_string().green().bold(),
        total.to_string().bold()
    );
    println!("{}", "═══════════════════════════════════════════".cyan());
    println!();
}
