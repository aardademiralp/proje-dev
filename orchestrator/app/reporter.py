"""
ISU-SecOps-Orchestrator — Vulnerability Report Generator
=========================================================
Tarama sonuçlarını OWASP Top 10 eşlemesi, CVE referansları ve
CVSS-benzeri risk skorlaması ile kapsamlı Markdown raporlarına
dönüştüren profesyonel siber güvenlik rapor motoru.

Author: ISU-SecOps Team
Version: 1.0.0
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import AppSettings, get_settings
from .scanner import HostInfo, PortInfo, ScanResult, ScanStatus
from .utils import format_duration, get_logger, utc_now

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) Eşleme Tablosu
# ---------------------------------------------------------------------------

OWASP_MAPPING: dict[int, dict[str, str]] = {
    21: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "FTP, şifrelenmemiş veri transferi nedeniyle güvensizdir. "
            "Kimlik bilgileri ve veriler açık metin olarak iletilir."
        ),
        "cwe": "CWE-319",
        "cve_examples": ["CVE-2011-2523", "CVE-2015-3306"],
    },
    22: {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": (
            "SSH zayıf konfigürasyonlar veya eski sürümler nedeniyle "
            "brute-force ve credential stuffing saldırılarına açık olabilir."
        ),
        "cwe": "CWE-287",
        "cve_examples": ["CVE-2023-38408", "CVE-2016-6515"],
    },
    23: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "Telnet, kimlik doğrulama ve veri iletiminde şifreleme kullanmaz. "
            "Tüm trafik açık metin olarak ağda dolaşır. "
            "DERHAL kullanımdan kaldırılmalıdır."
        ),
        "cwe": "CWE-319",
        "cve_examples": ["CVE-2011-4862"],
    },
    80: {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": (
            "HTTP, şifrelenmemiş iletişim kullanır. "
            "Hassas veriler (oturum çerezleri, form verileri) MITM saldırılarına açıktır."
        ),
        "cwe": "CWE-311",
        "cve_examples": [],
    },
    135: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "MS-RPC servisi, uzaktan kod yürütme güvenlik açıklarına tarihsel olarak "
            "çok sayıda kez kurban gitmiştir. İnternet'e açık olmamalıdır."
        ),
        "cwe": "CWE-269",
        "cve_examples": ["CVE-2003-0352", "CVE-2017-8461"],
    },
    139: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "NetBIOS servisi, ağ adı çözümleme saldırılarına (LLMNR/NBT-NS Poisoning) "
            "ve bilgi ifşasına yol açabilir."
        ),
        "cwe": "CWE-200",
        "cve_examples": ["CVE-2017-0145"],
    },
    161: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "SNMP v1/v2c, 'community string' adı verilen zayıf bir kimlik doğrulama "
            "mekanizması kullanır. Ağ cihazlarına yetkisiz erişim riski taşır."
        ),
        "cwe": "CWE-284",
        "cve_examples": ["CVE-2017-6742", "CVE-2002-0013"],
    },
    389: {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": (
            "LDAP anonim bağlantıya izin veriyorsa dizin bilgilerinin sızdırılmasına "
            "neden olabilir. LDAPS (636) kullanılması önerilir."
        ),
        "cwe": "CWE-287",
        "cve_examples": ["CVE-2021-22905"],
    },
    445: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "SMB protokolü, EternalBlue gibi kritik güvenlik açıkları nedeniyle "
            "WannaCry ve NotPetya gibi yıkıcı saldırıların vektörü olmuştur. "
            "İnternet'e asla açık olmamalıdır."
        ),
        "cwe": "CWE-120",
        "cve_examples": ["CVE-2017-0143", "CVE-2017-0144", "CVE-2020-0796"],
    },
    1433: {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": (
            "MSSQL veritabanı portuna doğrudan internet erişimi, "
            "brute-force, SQL injection ve veri ihlali risklerini artırır."
        ),
        "cwe": "CWE-306",
        "cve_examples": ["CVE-2020-0618"],
    },
    1521: {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": (
            "Oracle DB portuna doğrudan internet erişimi ciddi veri ihlali "
            "riskleri taşır."
        ),
        "cwe": "CWE-306",
        "cve_examples": ["CVE-2012-1675"],
    },
    3306: {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": (
            "MySQL portuna doğrudan internet erişimi, yetkisiz veritabanı "
            "erişimine ve veri sızdırılmasına neden olabilir."
        ),
        "cwe": "CWE-306",
        "cve_examples": ["CVE-2016-6662"],
    },
    3389: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "RDP, brute-force, BlueKeep ve DejaBlue gibi kritik açıklara tarihsel "
            "olarak maruz kalmıştır. İnternet'e açık RDP, fidye yazılımı saldırılarının "
            "en yaygın giriş noktalarından biridir."
        ),
        "cwe": "CWE-307",
        "cve_examples": ["CVE-2019-0708", "CVE-2019-1181", "CVE-2022-21990"],
    },
    5432: {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": (
            "PostgreSQL portuna doğrudan internet erişimi, yetkisiz "
            "veritabanı erişimi ve veri ihlali riski oluşturur."
        ),
        "cwe": "CWE-306",
        "cve_examples": ["CVE-2019-9193"],
    },
    5900: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "VNC protokolü çoğunlukla zayıf kimlik doğrulama veya şifrelemesiz "
            "çalışır. Uzaktan masaüstü ele geçirme riski taşır."
        ),
        "cwe": "CWE-287",
        "cve_examples": ["CVE-2006-2369", "CVE-2019-15681"],
    },
    6379: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "Redis varsayılan olarak kimlik doğrulama gerektirmez. "
            "İnternet'e açık Redis sunucuları, tam veri erişimi ve "
            "uzaktan kod yürütme riski taşır."
        ),
        "cwe": "CWE-306",
        "cve_examples": ["CVE-2022-0543"],
    },
    27017: {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "MongoDB varsayılan olarak kimlik doğrulama gerektirmeden çalışabilir. "
            "İnternet'e açık örnekler büyük veri ihlallerine yol açmıştır."
        ),
        "cwe": "CWE-306",
        "cve_examples": ["CVE-2021-32050"],
    },
}

# ---------------------------------------------------------------------------
# Sıkılaştırma Önerileri (Remediation) Tablosu
# ---------------------------------------------------------------------------

REMEDIATION_MAPPING: dict[int, list[str]] = {
    21: [
        "FTP servisini devre dışı bırakın; bunun yerine **SFTP (SSH Dosya Aktarım Protokolü)** veya **FTPS** kullanın.",
        "Geçici dosya transferleri için güvenli alternatifleri (SCP, rsync over SSH) değerlendirin.",
        "Zorunlu kullanım halinde, FTP'yi yalnızca VPN üzerinden erişilebilir yapın.",
        "Güçlü parola politikaları uygulayın ve anonymous FTP erişimini devre dışı bırakın.",
    ],
    22: [
        "SSH konfigürasyonunu sıkılaştırın (`/etc/ssh/sshd_config`):",
        "  - `PermitRootLogin no` — Root ile doğrudan giriş yasağı",
        "  - `PasswordAuthentication no` — Parola kimlik doğrulaması yerine SSH anahtar çifti kullanın",
        "  - `MaxAuthTries 3` — Başarısız giriş denemelerini sınırlandırın",
        "  - `AllowUsers` ile yalnızca yetkili kullanıcılara izin verin",
        "SSH'i varsayılan 22 portundan farklı bir porta taşıyın (security by obscurity).",
        "**Fail2ban** veya benzeri bir araç ile brute-force koruması uygulayın.",
        "SSH erişimini VPN veya güvenilir IP aralıklarıyla kısıtlayın.",
    ],
    23: [
        "**DERHAL** Telnet servisini devre dışı bırakın: `systemctl disable telnet`",
        "SSH (port 22) ile değiştirin: `apt install openssh-server`",
        "Güvenlik duvarında Telnet portunu (23) tamamen bloke edin.",
        "Tüm aktif Telnet oturumlarını kapatın ve kimlik bilgilerini değiştirin.",
    ],
    80: [
        "HTTPS'e (port 443) yönlendirme uygulayın. HTTP trafiğini HTTPS'e otomatik redirect edin.",
        "**Let's Encrypt** ile ücretsiz TLS sertifikası edinin.",
        "**HSTS (HTTP Strict Transport Security)** başlığını etkinleştirin:",
        "  `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`",
        "TLS 1.2 ve 1.3'ü zorunlu kılın; TLS 1.0/1.1 ve SSL 3.0'ı devre dışı bırakın.",
    ],
    139: [
        "NetBIOS over TCP/IP'yi devre dışı bırakın (özellikle internet'e bakan arayüzlerde).",
        "LLMNR ve NBT-NS'yi devre dışı bırakın (GPO ile).",
        "Ağ segmentasyonu uygulayarak NetBIOS trafiğini yalnızca iç ağla sınırlayın.",
    ],
    161: [
        "SNMP v1 ve v2c'yi devre dışı bırakın; **SNMP v3** kullanın (güçlü kimlik doğrulama ve şifreleme).",
        "Varsayılan 'public' ve 'private' community string'lerini değiştirin.",
        "SNMP erişimini yalnızca ağ yönetim sistemlerine (NMS) kısıtlayın.",
        "Güvenlik duvarında UDP 161/162 portlarını harici erişime kapatın.",
    ],
    389: [
        "LDAP'ı şifrelenmiş **LDAPS** (port 636) ile değiştirin veya STARTTLS kullanın.",
        "Anonim LDAP bağlantılarını devre dışı bırakın.",
        "LDAP erişimini yalnızca yetkili uygulama sunucularıyla sınırlayın.",
    ],
    445: [
        "SMBv1'i **DERHAL** devre dışı bırakın: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`",
        "İnternet'e bakan güvenlik duvarında TCP 445 portunu kesinlikle bloke edin.",
        "**MS17-010** yamasını ve tüm güncel güvenlik yamalarını uygulayın.",
        "SMBv3 şifrelemesini etkinleştirin: `Set-SmbServerConfiguration -EncryptData $true`",
        "Ağ segmentasyonu uygulayın; SMB trafiğini yalnızca iç ağla sınırlayın.",
    ],
    1433: [
        "MSSQL portunu güvenlik duvarıyla kısıtlayın; yalnızca uygulama sunucusunun IP'sine izin verin.",
        "Varsayılan 'sa' hesabını devre dışı bırakın veya yeniden adlandırın.",
        "SQL Server'ı minimum ayrıcalık ilkesiyle (least privilege) çalıştırın.",
        "SQL Server'a VPN veya özel ağ üzerinden erişimi zorunlu kılın.",
        "Tüm güvenlik yamalarını ve hizmet paketlerini uygulayın.",
    ],
    3306: [
        "MySQL/MariaDB'yi güvenlik duvarıyla kısıtlayın; uzaktan erişimi kapatın.",
        "`bind-address = 127.0.0.1` ile MySQL'i yalnızca yerel bağlantı dinleyecek şekilde ayarlayın.",
        "Uzaktan erişim gerekiyorsa SSH tüneli kullanın.",
        "Root kullanıcısı için `host`'u `localhost` ile sınırlandırın.",
        "Gereksiz kullanıcı hesaplarını ve ayrıcalıklarını kaldırın.",
    ],
    3389: [
        "RDP'yi internet'e **asla** doğrudan açmayın.",
        "**Network Level Authentication (NLA)** etkinleştirin.",
        "RDP erişimini **VPN** veya Jump Host üzerinden zorunlu kılın.",
        "**Güvenlik duvarında** RDP portunu (3389) harici erişime tamamen kapatın.",
        "Account lockout politikası ile brute-force saldırılarını engelleyin.",
        "**BlueKeep (CVE-2019-0708)** ve ilgili yamaları uygulayın.",
        "Çok faktörlü kimlik doğrulama (MFA) uygulayın.",
    ],
    5432: [
        "PostgreSQL portunu güvenlik duvarıyla kısıtlayın.",
        "`postgresql.conf` dosyasında `listen_addresses = 'localhost'` olarak ayarlayın.",
        "Uzaktan erişim gerekiyorsa SSL bağlantısı zorunlu kılın: `ssl = on`",
        "`pg_hba.conf` ile yalnızca yetkili IP'lere bağlantı izni verin.",
    ],
    5900: [
        "VNC erişimini **SSH tüneli** üzerinden yapın: `ssh -L 5901:localhost:5900 user@host`",
        "Güvenlik duvarında TCP 5900-5910 portlarını harici erişime kapatın.",
        "VNC sunucusuna güçlü parola konfigüre edin.",
        "**TigerVNC** veya **RealVNC** gibi şifreleme destekli çözümleri tercih edin.",
    ],
    6379: [
        "Redis konfigürasyonunda kimlik doğrulamayı etkinleştirin: `requirepass <güçlü_parola>`",
        "`bind 127.0.0.1` ile Redis'i yalnızca yerel bağlantılara kısıtlayın.",
        "**Redis 6+** sürümlerinde ACL (Access Control List) kullanın.",
        "TLS şifreleme ile Redis bağlantılarını güvenli hale getirin.",
        "**Redis'i root olmayan bir kullanıcı** altında çalıştırın.",
    ],
    27017: [
        "MongoDB'de kimlik doğrulamayı etkinleştirin: `mongod --auth`",
        "`bindIp: 127.0.0.1` ile MongoDB'yi yalnızca yerel bağlantılara kısıtlayın.",
        "Güvenlik duvarında TCP 27017-27019 portlarını harici erişime kapatın.",
        "MongoDB TLS/SSL şifrelemesini etkinleştirin.",
        "Minimum ayrıcalık ilkesiyle veritabanı kullanıcıları oluşturun.",
    ],
}

# Genel sıkılaştırma önerileri (tüm taramalara eklenir)
GENERAL_RECOMMENDATIONS: list[str] = [
    "**Güvenlik Duvarı (Firewall):** Yalnızca gerekli portları açık tutun; varsayılan-reddet (default-deny) politikası uygulayın.",
    "**Yama Yönetimi:** Tüm sistem ve uygulamaları düzenli olarak güncelleyin. CISA KEV kataloğunu takip edin.",
    "**Ağ Segmentasyonu:** Kritik sistemleri ayrı ağ segmentlerine ayırın; DMZ mimarisi uygulayın.",
    "**Güçlü Kimlik Doğrulama:** Tüm servisler için çok faktörlü kimlik doğrulama (MFA) uygulayın.",
    "**İzleme ve Loglama:** Tüm ağ trafiğini ve sistem loglarını merkezi bir SIEM çözümüyle izleyin.",
    "**Zafiyet Yönetimi:** Düzenli penetrasyon testi ve zafiyet taraması programı yürütün.",
]

# ---------------------------------------------------------------------------
# Rapor Veri Modeli
# ---------------------------------------------------------------------------


@dataclass
class FindingSummary:
    """Rapor için özet bulgu istatistikleri."""

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_hosts: int = 0
    total_open_ports: int = 0
    owasp_categories: set[str] = field(default_factory=set)

    @property
    def total_findings(self) -> int:
        return self.critical_count + self.high_count + self.medium_count + self.low_count

    @property
    def overall_risk(self) -> str:
        if self.critical_count > 0:
            return "CRITICAL"
        if self.high_count > 0:
            return "HIGH"
        if self.medium_count > 0:
            return "MEDIUM"
        return "LOW"

    @property
    def risk_emoji(self) -> str:
        mapping = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }
        return mapping.get(self.overall_risk, "⚪")


# ---------------------------------------------------------------------------
# Ana Rapor Üretici Sınıfı
# ---------------------------------------------------------------------------


class VulnerabilityReportGenerator:
    """
    Tarama sonuçlarını profesyonel siber güvenlik denetim raporuna
    dönüştüren merkezi rapor üretici sınıfı.

    Üretilen rapor şu bölümleri içerir:
        1. Yönetici Özeti (Executive Summary)
        2. Kapsam ve Metodoloji
        3. Teknik Bulgular (host/port bazlı, risk sıralı)
        4. OWASP Top 10 Eşleme Analizi
        5. Sıkılaştırma Önerileri (Remediation)
        6. Risk Matrisi
        7. Sonuç

    Usage::

        generator = VulnerabilityReportGenerator()
        report_path = generator.generate(scan_result)
        print(f"Rapor kaydedildi: {report_path}")
    """

    def __init__(self, settings: AppSettings | None = None) -> None:
        self._settings = settings or get_settings()

    # ------------------------------------------------------------------
    # Genel Rapor Üretimi
    # ------------------------------------------------------------------

    def generate(self, scan_result: ScanResult) -> Path:
        """
        ScanResult'tan eksiksiz bir Markdown raporu üretir ve diske kaydeder.

        Args:
            scan_result: Tamamlanmış tarama sonucu.

        Returns:
            Kaydedilen rapor dosyasının ``Path`` nesnesi.

        Raises:
            IOError: Rapor dosyası yazılamazsa.
        """
        logger.info(
            "Rapor üretimi başlatıldı.",
            extra={
                "task_id": scan_result.task_id,
                "target": scan_result.target,
                "hosts": len(scan_result.hosts),
            },
        )

        summary = self._compute_summary(scan_result)
        content = self._render_report(scan_result, summary)
        report_path = self._save_report(scan_result, content)

        logger.info(
            "Rapor başarıyla üretildi.",
            extra={
                "task_id": scan_result.task_id,
                "report_path": str(report_path),
                "overall_risk": summary.overall_risk,
            },
        )

        return report_path

    # ------------------------------------------------------------------
    # İstatistik Hesaplama
    # ------------------------------------------------------------------

    def _compute_summary(self, scan_result: ScanResult) -> FindingSummary:
        """Tüm bulgulardan özet istatistikleri hesaplar."""
        summary = FindingSummary(
            total_hosts=len(scan_result.hosts),
            total_open_ports=scan_result.total_open_ports,
        )

        for host in scan_result.hosts:
            for port in host.open_ports:
                risk = port.risk_level
                if risk == "CRITICAL":
                    summary.critical_count += 1
                elif risk == "HIGH":
                    summary.high_count += 1
                elif risk == "MEDIUM":
                    summary.medium_count += 1
                else:
                    summary.low_count += 1

                owasp = OWASP_MAPPING.get(port.port)
                if owasp:
                    summary.owasp_categories.add(f"{owasp['id']} — {owasp['name']}")

        return summary

    # ------------------------------------------------------------------
    # Rapor İçeriği Oluşturma
    # ------------------------------------------------------------------

    def _render_report(self, scan_result: ScanResult, summary: FindingSummary) -> str:
        """Tüm rapor bölümlerini birleştirerek tam Markdown içeriği üretir."""
        sections = [
            self._render_header(scan_result, summary),
            self._render_executive_summary(scan_result, summary),
            self._render_scope_and_methodology(scan_result),
            self._render_risk_matrix(summary),
            self._render_technical_findings(scan_result),
            self._render_owasp_analysis(summary),
        ]

        if self._settings.report_include_remediation:
            sections.append(self._render_remediation(scan_result))

        sections.append(self._render_conclusion(scan_result, summary))
        sections.append(self._render_footer(scan_result))

        return "\n\n---\n\n".join(sections)

    def _render_header(self, scan_result: ScanResult, summary: FindingSummary) -> str:
        """Rapor başlığı ve meta bilgilerini üretir."""
        now = utc_now()
        classification = self._get_classification(summary)

        return textwrap.dedent(f"""\
            # 🛡️ ISU-SecOps Güvenlik Denetim Raporu

            ```
            ╔══════════════════════════════════════════════════════════════╗
            ║          ISU-SECOPS VULNERABILITY ASSESSMENT REPORT          ║
            ║                   CONFIDENTIAL // TLP:RED                   ║
            ╚══════════════════════════════════════════════════════════════╝
            ```

            | Alan                  | Bilgi                                              |
            |-----------------------|----------------------------------------------------|
            | **Rapor Tarihi**      | {now.strftime("%d %B %Y, %H:%M UTC")}              |
            | **Görev Kimliği**     | `{scan_result.task_id}`                            |
            | **Tarama Hedefi**     | `{scan_result.target}`                             |
            | **Genel Risk Seviyesi** | {summary.risk_emoji} **{summary.overall_risk}**  |
            | **Gizlilik Sınıfı**   | {classification}                                   |
            | **Hazırlayan**        | {self._settings.report_organization}               |
            | **Rapor Motoru**      | ISU-SecOps-Orchestrator v{self._settings.app_version} |

            > ⚠️ **GİZLİLİK UYARISI:** Bu rapor hassas güvenlik bilgileri içermektedir.
            > Yalnızca yetkili personel tarafından incelenmelidir.
            > Yetkisiz erişim veya ifşaat yasal yaptırımlara konu olabilir.
        """)

    def _render_executive_summary(
        self, scan_result: ScanResult, summary: FindingSummary
    ) -> str:
        """Yönetici özeti bölümünü üretir."""
        duration_str = "N/A"
        if scan_result.duration_seconds:
            duration_str = format_duration(scan_result.duration_seconds)

        owasp_list = "\n".join(f"- {cat}" for cat in sorted(summary.owasp_categories))
        if not owasp_list:
            owasp_list = "- Kritik OWASP kategorisi tespit edilmedi."

        return textwrap.dedent(f"""\
            ## 📋 1. Yönetici Özeti (Executive Summary)

            Bu rapor, **{scan_result.target}** hedefi üzerinde ISU-SecOps-Engine
            tarafından gerçekleştirilen otomatik güvenlik taramasının bulgularını
            özetlemektedir.

            ### 1.1 Özet İstatistikler

            | Metrik                        | Değer                          |
            |-------------------------------|--------------------------------|
            | Tarama Hedefi                 | `{scan_result.target}`         |
            | Taranan Host Sayısı           | **{summary.total_hosts}**      |
            | Toplam Açık Port              | **{summary.total_open_ports}** |
            | Kritik Bulgular               | 🔴 **{summary.critical_count}** |
            | Yüksek Bulgular               | 🟠 **{summary.high_count}**    |
            | Orta Bulgular                 | 🟡 **{summary.medium_count}**  |
            | Düşük Bulgular                | 🟢 **{summary.low_count}**    |
            | Tarama Süresi                 | {duration_str}                 |
            | **Genel Risk Seviyesi**       | {summary.risk_emoji} **{summary.overall_risk}** |

            ### 1.2 Öne Çıkan Bulgular

            {owasp_list}

            ### 1.3 Acil Eylem Gerektiren Durumlar

            {"⚠️ **DERHAL MÜDAHALE GEREKTİREN** kritik güvenlik açıkları tespit edilmiştir. Detaylar için bkz. Bölüm 4." if summary.critical_count > 0 else "✅ Acil müdahale gerektiren kritik bulgu tespit edilmemiştir."}
        """)

    def _render_scope_and_methodology(self, scan_result: ScanResult) -> str:
        """Kapsam ve metodoloji bölümünü üretir."""
        started = scan_result.started_at.strftime("%d.%m.%Y %H:%M UTC")
        completed = (
            scan_result.completed_at.strftime("%d.%m.%Y %H:%M UTC")
            if scan_result.completed_at
            else "N/A"
        )

        return textwrap.dedent(f"""\
            ## 🎯 2. Kapsam ve Metodoloji

            ### 2.1 Değerlendirme Kapsamı

            | Alan          | Detay                          |
            |---------------|--------------------------------|
            | Hedef         | `{scan_result.target}`         |
            | Başlangıç     | {started}                      |
            | Bitiş         | {completed}                    |
            | Değerlendirme Türü | Otomatik Ağ ve Servis Keşfi |
            | Metodoloji    | Black-Box / External           |

            ### 2.2 Kullanılan Araçlar ve Teknikler

            | Araç/Teknik            | Açıklama                                           |
            |------------------------|----------------------------------------------------|
            | **ISU-SecOps-Engine**  | Rust tabanlı yüksek performanslı port tarayıcı     |
            | **Port Tarama**        | TCP/UDP bağlantı tabanlı port keşfi               |
            | **Servis Tespiti**     | Banner grabbing ve protokol analizi                |
            | **Risk Sınıflandırması** | CVSS v3.1 tabanlı özelleştirilmiş risk modeli    |
            | **OWASP Eşlemesi**     | OWASP Top 10 2021 referans çerçevesi              |

            ### 2.3 Değerlendirme Sınırlamaları

            > **NOT:** Bu değerlendirme **otomatik keşif** tabanlıdır. Manuel sızma testi,
            > uygulama katmanı analizi ve sosyal mühendislik senaryoları bu raporun kapsamı
            > dışındadır. Kapsamlı bir güvenlik değerlendirmesi için manuel penetrasyon
            > testi önerilmektedir.
        """)

    def _render_risk_matrix(self, summary: FindingSummary) -> str:
        """CVSS-benzeri risk matrisi bölümünü üretir."""
        total = max(summary.total_findings, 1)

        critical_bar = self._progress_bar(summary.critical_count, total, 20)
        high_bar = self._progress_bar(summary.high_count, total, 20)
        medium_bar = self._progress_bar(summary.medium_count, total, 20)
        low_bar = self._progress_bar(summary.low_count, total, 20)

        return textwrap.dedent(f"""\
            ## 📊 3. Risk Matrisi

            ### 3.1 Bulgu Dağılımı

            ```
            Risk Seviyesi    Sayı   Dağılım
            ─────────────────────────────────────────────────
            🔴 CRITICAL      {summary.critical_count:>4}   {critical_bar}
            🟠 HIGH          {summary.high_count:>4}   {high_bar}
            🟡 MEDIUM        {summary.medium_count:>4}   {medium_bar}
            🟢 LOW           {summary.low_count:>4}   {low_bar}
            ─────────────────────────────────────────────────
            TOPLAM           {summary.total_findings:>4}
            ```

            ### 3.2 Risk Tanımları

            | Seviye      | CVSS Skoru | Tanım                                                    |
            |-------------|------------|----------------------------------------------------------|
            | 🔴 CRITICAL | 9.0 – 10.0 | Derhal müdahale gerektiren kritik açıklar                |
            | 🟠 HIGH     | 7.0 – 8.9  | Öncelikli olarak kapatılması gereken yüksek riskli açıklar |
            | 🟡 MEDIUM   | 4.0 – 6.9  | Planlı yamalar ile kapatılması gereken orta riskli açıklar |
            | 🟢 LOW      | 0.1 – 3.9  | Düşük öncelikli, uzun vadede adreslenebilir açıklar      |
        """)

    def _render_technical_findings(self, scan_result: ScanResult) -> str:
        """Host bazında teknik bulgular bölümünü üretir."""
        if not scan_result.hosts:
            return textwrap.dedent("""\
                ## 🔍 4. Teknik Bulgular

                > ℹ️ Taramada erişilebilir host veya açık port tespit edilmedi.
            """)

        sections = ["## 🔍 4. Teknik Bulgular\n"]

        for i, host in enumerate(scan_result.hosts, 1):
            sections.append(self._render_host_findings(host, i))

        return "\n".join(sections)

    def _render_host_findings(self, host: HostInfo, index: int) -> str:
        """Tek bir host için bulgu bölümü üretir."""
        lines = [f"### 4.{index} Host: `{host.display_name}`\n"]

        # Host bilgileri
        lines.append("**Host Bilgileri:**\n")
        lines.append(f"| Alan | Değer |")
        lines.append(f"|------|-------|")
        lines.append(f"| IP Adresi | `{host.address}` |")
        if host.hostname:
            lines.append(f"| Hostname | `{host.hostname}` |")
        lines.append(f"| Durum | `{host.status}` |")
        if host.os_detection:
            lines.append(f"| İşletim Sistemi | `{host.os_detection}` |")
        lines.append(f"| Açık Port Sayısı | **{len(host.open_ports)}** |")
        lines.append("")

        if not host.open_ports:
            lines.append("> ✅ Bu host üzerinde açık port tespit edilmedi.\n")
            return "\n".join(lines)

        # Port bulguları tablosu
        lines.append("**Açık Port Bulguları:**\n")
        lines.append("| Port | Protokol | Servis | Versiyon | Risk | OWASP |")
        lines.append("|------|----------|--------|----------|------|-------|")

        # Risk seviyesine göre sırala (Critical > High > Medium > Low)
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_ports = sorted(
            host.open_ports, key=lambda p: risk_order.get(p.risk_level, 4)
        )

        for port in sorted_ports:
            owasp = OWASP_MAPPING.get(port.port)
            owasp_ref = f"`{owasp['id']}`" if owasp else "-"
            risk_indicator = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🟢 LOW",
            }.get(port.risk_level, "⚪ UNKNOWN")

            version_str = port.version or "-"
            service_str = port.service or "-"

            lines.append(
                f"| `{port.port}/{port.protocol}` | {port.protocol.upper()} "
                f"| {service_str} | `{version_str}` | {risk_indicator} | {owasp_ref} |"
            )

        lines.append("")

        # Kritik portlar için detaylı analiz
        critical_ports = [p for p in sorted_ports if p.risk_level in ("CRITICAL", "HIGH")]
        if critical_ports:
            lines.append("**🚨 Kritik Bulgu Analizleri:**\n")
            for port in critical_ports:
                owasp = OWASP_MAPPING.get(port.port)
                if owasp:
                    cve_str = ", ".join(f"`{cve}`" for cve in owasp.get("cve_examples", []))
                    lines.append(f"#### Port {port.port}/{port.protocol} — {port.service}\n")
                    lines.append(f"- **Risk Seviyesi:** {port.risk_level}")
                    lines.append(f"- **OWASP Kategorisi:** {owasp['id']} — {owasp['name']}")
                    lines.append(f"- **CWE:** [{owasp['cwe']}](https://cwe.mitre.org/data/definitions/{owasp['cwe'].split('-')[1]}.html)")
                    lines.append(f"- **Risk Açıklaması:** {owasp['description']}")
                    if cve_str:
                        lines.append(f"- **Bilinen CVE Örnekleri:** {cve_str}")
                    if port.banner:
                        lines.append(f"- **Tespit Edilen Banner:** `{port.banner}`")
                    lines.append("")

        return "\n".join(lines)

    def _render_owasp_analysis(self, summary: FindingSummary) -> str:
        """OWASP Top 10 analiz bölümünü üretir."""
        if not summary.owasp_categories:
            return textwrap.dedent("""\
                ## 🏆 5. OWASP Top 10 Analizi

                > ✅ Tespit edilen bulgular OWASP Top 10 kategorileriyle eşleşmiyor.
            """)

        cat_list = "\n".join(
            f"- **{cat}**" for cat in sorted(summary.owasp_categories)
        )

        return textwrap.dedent(f"""\
            ## 🏆 5. OWASP Top 10 Analizi

            Tarama sonuçları OWASP Top 10 (2021) güvenlik açığı kategorileriyle
            karşılaştırılmış olup aşağıdaki kategorilerde bulgular tespit edilmiştir:

            {cat_list}

            > 📚 Referans: [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
            > National Vulnerability Database: [https://nvd.nist.gov](https://nvd.nist.gov)
        """)

    def _render_remediation(self, scan_result: ScanResult) -> str:
        """Sıkılaştırma önerileri bölümünü üretir."""
        lines = ["## 🔧 6. Sıkılaştırma Önerileri (Remediation)\n"]
        lines.append(
            "> **Öncelik Sırası:** CRITICAL → HIGH → MEDIUM → LOW\n"
        )

        # Port bazlı öneriler
        all_ports = [p for h in scan_result.hosts for p in h.open_ports]
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_ports = sorted(
            all_ports, key=lambda p: risk_order.get(p.risk_level, 4)
        )

        # Tekrar eden portları kaldır
        seen_ports: set[int] = set()
        unique_ports = []
        for p in sorted_ports:
            if p.port not in seen_ports:
                seen_ports.add(p.port)
                unique_ports.append(p)

        has_specific = False
        for port in unique_ports:
            remediations = REMEDIATION_MAPPING.get(port.port)
            if remediations:
                has_specific = True
                risk_indicator = {
                    "CRITICAL": "🔴 CRITICAL",
                    "HIGH": "🟠 HIGH",
                    "MEDIUM": "🟡 MEDIUM",
                    "LOW": "🟢 LOW",
                }.get(port.risk_level, "⚪")

                lines.append(
                    f"### 6.{len([p for p in seen_ports if p <= port.port])} "
                    f"Port {port.port} ({port.service}) — {risk_indicator}\n"
                )
                for rec in remediations:
                    lines.append(f"- {rec}")
                lines.append("")

        if not has_specific:
            lines.append(
                "- Tespit edilen portlar için özelleştirilmiş öneri mevcut değil. "
                "Genel güvenlik sıkılaştırma önerilerine bakınız.\n"
            )

        # Genel öneriler
        lines.append("### Genel Güvenlik Sıkılaştırma Önerileri\n")
        for rec in GENERAL_RECOMMENDATIONS:
            lines.append(f"- {rec}")

        return "\n".join(lines)

    def _render_conclusion(
        self, scan_result: ScanResult, summary: FindingSummary
    ) -> str:
        """Sonuç ve tavsiyeler bölümünü üretir."""
        if summary.critical_count > 0:
            urgency = (
                "**DERHAL** müdahale gerekmektedir. Kritik bulgular, sisteme yetkisiz "
                "erişim, veri ihlali veya hizmet kesintisi riskini önemli ölçüde "
                "artırmaktadır."
            )
            next_steps = [
                "Kritik bulgular için acil yama planı hazırlayın (24-48 saat).",
                "Etkilenen sistemleri ağdan izole etmeyi değerlendirin.",
                "Güvenlik olayı müdahale prosedürünü (Incident Response) başlatın.",
                "Tüm sıkılaştırma adımlarını uyguladıktan sonra doğrulama taraması yapın.",
            ]
        elif summary.high_count > 0:
            urgency = (
                "Yüksek riskli bulgular tespit edilmiştir. 1 hafta içinde "
                "sıkılaştırma adımlarının uygulanması önerilmektedir."
            )
            next_steps = [
                "Yüksek riskli bulgular için 1 hafta içinde yama planı hazırlayın.",
                "Etkilenen servisleri gözden geçirin ve gereksizleri devre dışı bırakın.",
                "Güvenlik duvarı kurallarını güçlendirin.",
                "Sıkılaştırma sonrası doğrulama taraması yapın.",
            ]
        else:
            urgency = (
                "Kritik veya yüksek riskli bulgu tespit edilmemiştir. "
                "Tespit edilen orta/düşük riskli bulgular planlanmış bakım "
                "döngülerinde adreslenebilir."
            )
            next_steps = [
                "Orta riskli bulgular için 30 gün içinde yama planı hazırlayın.",
                "Düzenli periyodik tarama programı oluşturun.",
                "Güvenlik politika ve prosedürlerinizi gözden geçirin.",
            ]

        steps_list = "\n".join(f"{i}. {step}" for i, step in enumerate(next_steps, 1))

        return textwrap.dedent(f"""\
            ## 📌 7. Sonuç ve Tavsiyeler

            {urgency}

            ### Önerilen Sonraki Adımlar

            {steps_list}

            ### Düzenli Güvenlik Değerlendirmesi

            Bu otomatik tarama, sürekli güvenlik programının yalnızca bir bileşenidir.
            Kapsamlı bir güvenlik duruşu için aşağıdakiler de önerilmektedir:

            - **Aylık:** Otomatik zafiyet taramaları
            - **Çeyreklik:** Manuel penetrasyon testi
            - **Yıllık:** Kapsamlı Red Team değerlendirmesi
            - **Sürekli:** Güvenlik log izleme ve SIEM entegrasyonu
        """)

    def _render_footer(self, scan_result: ScanResult) -> str:
        """Rapor alt bilgisini üretir."""
        return textwrap.dedent(f"""\
            ## 📜 Ek Bilgiler

            ### Referanslar

            | Kaynak | URL |
            |--------|-----|
            | OWASP Top 10 2021 | https://owasp.org/www-project-top-ten/ |
            | NVD (CVE Database) | https://nvd.nist.gov |
            | CISA KEV Kataloğu | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
            | CWE Listesi | https://cwe.mitre.org |
            | CVSS Kalkülatör | https://www.first.org/cvss/calculator/3.1 |

            ### Raporlama Bilgileri

            | Alan | Değer |
            |------|-------|
            | Görev Kimliği | `{scan_result.task_id}` |
            | Rapor Formatı | Markdown (GitHub Compatible) |
            | Oluşturulma Zamanı | {utc_now().isoformat()} |
            | Motor Sürümü | ISU-SecOps-Orchestrator v{self._settings.app_version} |

            ---

            *Bu rapor ISU-SecOps-Orchestrator tarafından otomatik olarak üretilmiştir.*
            *Sorularınız için güvenlik ekibinizle iletişime geçin.*
        """)

    # ------------------------------------------------------------------
    # Yardımcı Metodlar
    # ------------------------------------------------------------------

    @staticmethod
    def _progress_bar(value: int, total: int, width: int = 20) -> str:
        """ASCII ilerleme çubuğu üretir."""
        if total == 0:
            filled = 0
        else:
            filled = int((value / total) * width)
        bar = "█" * filled + "░" * (width - filled)
        pct = f"{(value / total * 100):.0f}%" if total > 0 else "0%"
        return f"[{bar}] {value} ({pct})"

    @staticmethod
    def _get_classification(summary: FindingSummary) -> str:
        """Risk seviyesine göre gizlilik sınıflandırması döndürür."""
        mapping = {
            "CRITICAL": "🔴 **GİZLİ** (Confidential)",
            "HIGH": "🟠 **KISITLI** (Restricted)",
            "MEDIUM": "🟡 **DAHİLİ** (Internal)",
            "LOW": "🟢 **KAMUYA AÇIK** (Public)",
        }
        return mapping.get(summary.overall_risk, "⚪ Sınıflandırılmamış")

    # ------------------------------------------------------------------
    # Disk Kaydetme
    # ------------------------------------------------------------------

    def _save_report(self, scan_result: ScanResult, content: str) -> Path:
        """
        Raporu tarih damgalı dosya adıyla disk üzerine kaydeder.

        Dosya adı formatı: ``isu_secops_<target>_<YYYYMMDD_HHMMSS>.md``

        Args:
            scan_result: Kaynak tarama sonucu.
            content: Markdown rapor içeriği.

        Returns:
            Kaydedilen dosyanın ``Path`` nesnesi.
        """
        # Hedef adını dosya sistemi güvenli hale getir
        safe_target = (
            scan_result.target
            .replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
            .replace(".", "-")
        )

        timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
        filename = f"isu_secops_{safe_target}_{timestamp}.md"
        report_path = self._settings.reports_dir / filename

        report_path.write_text(content, encoding="utf-8")

        return report_path
