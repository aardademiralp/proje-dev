use clap::Parser;
use pentester::http_header_analyzer::{analyze_headers, check_tls, print_report};
use pentester::web_server::start_server;

/// ISU-SecOps-Engine — HTTP Header Analyzer
#[derive(Parser, Debug)]
#[command(name = "pentester", version = "0.2.0", about = "HTTP Güvenlik Header Analiz Aracı")]
struct Args {
    /// Hedef URL (örn: https://example.com)
    #[arg(short, long)]
    url: Option<String>,

    /// URL listesi içeren dosya (her satırda bir URL)
    #[arg(short, long)]
    file: Option<String>,

    /// JSON formatında çıktı ver
    #[arg(short, long, default_value_t = false)]
    json: bool,

    /// Web panelini başlat
    #[arg(short, long, default_value_t = false)]
    web: bool,

    /// TLS/SSL kontrolü yap
    #[arg(short, long, default_value_t = false)]
    tls: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.web {
        let _ = std::process::Command::new("firefox")
            .arg("http://localhost:8080")
            .spawn();
        start_server().await;
        return;
    }

    // Toplu URL analizi
    if let Some(file_path) = args.file {
        let content = std::fs::read_to_string(&file_path)
            .unwrap_or_else(|_| { eprintln!("Dosya okunamadi: {}", file_path); std::process::exit(1); });

        let urls: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        println!("Toplam {} URL analiz edilecek\n", urls.len());

        for url in urls {
            println!("Analiz ediliyor: {}", url);

            if args.tls {
                let tls = check_tls(url).await;
                println!("TLS: {} — {}", if tls.cert_valid { "Gecerli" } else { "Gecersiz" }, tls.note);
            }

            match analyze_headers(url).await {
                Ok(report) => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    } else {
                        print_report(&report);
                    }
                }
                Err(e) => eprintln!("Hata ({}): {}", url, e),
            }
        }
        return;
    }

    // Tekil URL analizi
    match args.url {
        Some(url) => {
            println!("\nHedef analiz ediliyor: {}\n", url);

            if args.tls {
                let tls = check_tls(&url).await;
                println!("TLS Durumu : {}", if tls.cert_valid { "Gecerli" } else { "Gecersiz" });
                println!("TLS Notu   : {}\n", tls.note);
            }

            match analyze_headers(&url).await {
                Ok(report) => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    } else {
                        print_report(&report);
                    }
                }
                Err(e) => {
                    eprintln!("Hata: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            eprintln!("URL veya --web parametresi gerekli!");
            eprintln!("Kullanim: cargo run -- --url https://example.com");
            eprintln!("TLS:      cargo run -- --url https://example.com --tls");
            eprintln!("Toplu:    cargo run -- --file urls.txt");
            eprintln!("Panel:    cargo run -- --web");
            std::process::exit(1);
        }
    }
}
