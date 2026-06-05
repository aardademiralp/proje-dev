"""
ISU-SecOps-Orchestrator — Utilities Module
==========================================
Yapısal JSON loglama, hedef doğrulama, görev ID üretimi ve
performans ölçümü için yardımcı bileşenler.

Author: ISU-SecOps Team
Version: 1.0.0
"""

from __future__ import annotations

import functools
import ipaddress
import json
import logging
import re
import sys
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Özel Log Formatter — Yapısal JSON
# ---------------------------------------------------------------------------


class JsonLogFormatter(logging.Formatter):
    """
    Python logging kayıtlarını tek satır JSON formatına dönüştüren formatter.

    Her log kaydı şu alanları içerir:
        - timestamp: ISO-8601 UTC zaman damgası
        - level: Log seviyesi (INFO, WARNING vb.)
        - logger: Logger adı
        - message: Log mesajı
        - module / function / line: Kaynak konum bilgisi
        - extra: Varsa ek bağlam alanları
        - exc_info: Varsa istisna iz bilgisi
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Ekstra bağlam alanları (logger.info("msg", extra={"task_id": "..."}))
        standard_keys = {
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "id", "levelname", "levelno", "lineno", "message",
            "module", "msecs", "msg", "name", "pathname", "process",
            "processName", "relativeCreated", "stack_info", "thread",
            "threadName", "taskName",
        }
        extra = {k: v for k, v in record.__dict__.items() if k not in standard_keys}
        if extra:
            payload["extra"] = extra

        # İstisna bilgisi
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, default=str)


class PlainLogFormatter(logging.Formatter):
    """İnsan okunabilir metin log formatı (geliştirme ortamı için)."""

    FORMAT = (
        "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
        " [%(module)s:%(lineno)d]"
    )

    def __init__(self) -> None:
        super().__init__(fmt=self.FORMAT, datefmt="%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Logger Fabrikası
# ---------------------------------------------------------------------------


def setup_logging(
    level: str = "INFO",
    fmt: str = "json",
    app_name: str = "isu-secops",
) -> None:
    """
    Uygulama genelinde loglama altyapısını yapılandırır.

    Bu fonksiyon uygulama başlangıcında (main.py'de lifespan içinde) bir kez
    çağrılmalıdır. Sonraki ``get_logger()`` çağrıları bu yapılandırmayı kullanır.

    Args:
        level: Python log seviyesi ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
        fmt: Log formatı ('json' veya 'text').
        app_name: Root logger adı.
    """
    root_logger = logging.getLogger(app_name)
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Mevcut handler'ları temizle (tekrar setup_logging çağrılarında duplikasyon önleme)
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonLogFormatter() if fmt == "json" else PlainLogFormatter()
    )
    root_logger.addHandler(handler)

    # Üçüncü parti kütüphane loglarını bastır
    for noisy_lib in ("uvicorn.access", "httpx", "asyncio"):
        logging.getLogger(noisy_lib).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    ``isu-secops.<name>`` hiyerarşisinde bir logger döndürür.

    Args:
        name: Logger alt adı (genellikle ``__name__`` değeri).

    Returns:
        Yapılandırılmış Python Logger nesnesi.

    Example::

        logger = get_logger(__name__)
        logger.info("Tarama başlatıldı", extra={"target": "192.168.1.1"})
    """
    qualified = f"isu-secops.{name}" if not name.startswith("isu-secops") else name
    return logging.getLogger(qualified)


# ---------------------------------------------------------------------------
# Görev ID Üretimi
# ---------------------------------------------------------------------------


def generate_task_id() -> str:
    """
    Kriptografik olarak güvenli, benzersiz bir görev kimliği üretir.

    Format: ``task-<uuid4-hex[:12]>``
    Örnek: ``task-a3f9c2b1d840``

    Returns:
        Benzersiz görev kimliği string'i.
    """
    return f"task-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Hedef Doğrulama
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

_CIDR_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
)


def sanitize_target(target: str) -> str:
    """
    Tarama hedefini temizler ve geçerliliğini doğrular.

    Kabul edilen formatlar:
        - IPv4 adresi: ``192.168.1.1``
        - IPv4 CIDR aralığı: ``192.168.1.0/24``
        - Hostname: ``internal.corp.com``

    Args:
        target: Doğrulanacak ham hedef string'i.

    Returns:
        Temizlenmiş (stripped) hedef string'i.

    Raises:
        ValueError: Hedef geçersiz formatsa.
    """
    target = target.strip()

    if not target:
        raise ValueError("Tarama hedefi boş olamaz.")

    if len(target) > 253:
        raise ValueError(f"Hedef çok uzun ({len(target)} karakter, max 253).")

    # IPv4 veya IPv6 adresi
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # CIDR notasyonu
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    # IP görünümlü ama geçersiz adresleri reddet (örn: 256.256.256.256)
    import re as _ipre
    if _ipre.match(r"^\d+(\.\d+)+$", target):
        raise ValueError(
            f"Geçersiz tarama hedefi: '{target}'. "
            "IPv4 adresi, CIDR notasyonu veya geçerli bir hostname bekleniyor."
        )

    # Hostname
    if _HOSTNAME_RE.match(target):
        return target

    raise ValueError(
        f"Geçersiz tarama hedefi: '{target}'. "
        "IPv4 adresi, CIDR notasyonu veya geçerli bir hostname bekleniyor."
    )


def is_private_address(target: str) -> bool:
    """
    Hedefin özel (RFC 1918) bir IP adresi veya aralığı olup olmadığını kontrol eder.

    Args:
        target: IP adresi veya CIDR string'i.

    Returns:
        True eğer adres özel ağ aralığındaysa.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        return network.is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Zaman ve Performans Yardımcıları
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    """Şu anki UTC zamanını timezone-aware datetime olarak döndürür."""
    return datetime.now(UTC)


def format_duration(seconds: float) -> str:
    """
    Saniye cinsinden süreyi okunabilir formata dönüştürür.

    Args:
        seconds: Süre (saniye).

    Returns:
        Biçimlendirilmiş süre string'i. Örn: '2m 34s', '45.3s'
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.0f}s"


def timed(logger_name: str | None = None) -> Callable[[F], F]:
    """
    Fonksiyon çalışma süresini otomatik olarak loglayan dekoratör fabrikası.

    Args:
        logger_name: Kullanılacak logger adı. None ise fonksiyonun modül adı kullanılır.

    Returns:
        Dekoratör.

    Example::

        @timed(logger_name=__name__)
        async def run_scan(target: str) -> ScanResult:
            ...
    """
    def decorator(func: F) -> F:
        _logger = get_logger(logger_name or func.__module__)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            _logger.debug(
                "Fonksiyon başlatılıyor.",
                extra={"function": func.__name__, "args_count": len(args)},
            )
            try:
                result = await func(*args, **kwargs)
                elapsed = time.perf_counter() - start
                _logger.info(
                    "Fonksiyon tamamlandı.",
                    extra={
                        "function": func.__name__,
                        "duration": format_duration(elapsed),
                    },
                )
                return result
            except Exception as exc:
                elapsed = time.perf_counter() - start
                _logger.error(
                    "Fonksiyon hata ile sonlandı.",
                    extra={
                        "function": func.__name__,
                        "duration": format_duration(elapsed),
                        "error": str(exc),
                    },
                )
                raise

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                elapsed = time.perf_counter() - start
                _logger.info(
                    "Fonksiyon tamamlandı.",
                    extra={
                        "function": func.__name__,
                        "duration": format_duration(elapsed),
                    },
                )
                return result
            except Exception as exc:
                elapsed = time.perf_counter() - start
                _logger.error(
                    "Fonksiyon hata ile sonlandı.",
                    extra={
                        "function": func.__name__,
                        "duration": format_duration(elapsed),
                        "error": str(exc),
                    },
                )
                raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Port Yardımcıları
# ---------------------------------------------------------------------------

WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Port numarasına göre servis adı döndürür.

    Args:
        port: Port numarası.
        protocol: Protokol ('tcp' veya 'udp').

    Returns:
        Bilinen servis adı veya 'Unknown'.
    """
    return WELL_KNOWN_SERVICES.get(port, "Unknown")
