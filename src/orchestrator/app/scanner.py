from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any

from .config import AppSettings, get_settings
from .utils import format_duration, get_logger, get_service_name, timed, utc_now

logger = get_logger(__name__)


class EngineError(Exception):
    """
    ISU-SecOps-Engine ile ilgili tüm hataların temel sınıfı.

    Attributes:
        message: İnsan okunabilir hata mesajı.
        stderr_output: Engine'den gelen stderr çıktısı (varsa).
        return_code: Proses dönüş kodu (varsa).
    """

    def __init__(
        self,
        message: str,
        *,
        stderr_output: str = "",
        return_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.stderr_output = stderr_output
        self.return_code = return_code

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"message={self.message!r}, "
            f"return_code={self.return_code!r})"
        )


class EngineNotFoundError(EngineError):
    """
    Rust binary'si belirtilen yolda bulunamadığında veya
    çalıştırma izni olmadığında fırlatılır.
    """


class EngineTimeoutError(EngineError):
    """
    Tarama süreci konfigürasyondaki ``scan_timeout`` süresini
    aştığında fırlatılır. Süreç otomatik olarak sonlandırılır.
    """

    def __init__(self, message: str, *, timeout: int, target: str) -> None:
        super().__init__(message)
        self.timeout = timeout
        self.target = target


class EngineOutputError(EngineError):
    """
    Engine çıktısı beklenen formatta (JSON veya yapılandırılmış metin)
    olmadığında fırlatılır.
    """


class EngineCrashError(EngineError):
    """
    Engine sıfırdan farklı bir dönüş koduyla çıktığında fırlatılır.
    """


class ScanStatus(Enum):
    """Tarama görevinin yaşam döngüsü durumları."""

    PENDING = auto()
    """Tarama kuyruğa alındı, henüz başlamadı."""

    RUNNING = auto()
    """Tarama aktif olarak devam ediyor."""

    COMPLETED = auto()
    """Tarama başarıyla tamamlandı."""

    FAILED = auto()
    """Tarama bir hata nedeniyle başarısız oldu."""

    TIMEOUT = auto()
    """Tarama zaman aşımına uğradı."""


@dataclass
class PortInfo:
    """Açık bir port ve bağlı servis hakkındaki bilgiler."""

    port: int
    """Port numarası (1-65535)."""

    protocol: str
    """Protokol ('tcp' veya 'udp')."""

    state: str
    """Port durumu ('open', 'filtered', 'closed')."""

    service: str = ""
    """Tespit edilen servis adı."""

    version: str = ""
    """Tespit edilen servis sürümü."""

    banner: str = ""
    """Servis banner'ı (varsa)."""

    def __post_init__(self) -> None:
        if not self.service:
            self.service = get_service_name(self.port, self.protocol)

    @property
    def risk_level(self) -> str:
        """
        Portun risk seviyesini belirler.
        """
        critical_ports = {21, 23, 135, 139, 445, 3389, 5900}
        high_ports = {25, 53, 161, 389, 1433, 1521, 5432, 6379, 27017}
        low_ports = {443, 465, 587, 636, 993, 995, 8443}

        if self.port in critical_ports:
            return "CRITICAL"
        if self.port in high_ports:
            return "HIGH"
        if self.port in low_ports:
            return "LOW"
        return "MEDIUM"


@dataclass
class HostInfo:
    """Taranan bir host hakkındaki bilgiler."""

    address: str
    """Host IP adresi."""

    hostname: str = ""
    """Çözümlenen hostname (varsa)."""

    status: str = "up"
    """Host durumu ('up' veya 'down')."""

    os_detection: str = ""
    """Tespit edilen işletim sistemi (varsa)."""

    open_ports: list[PortInfo] = field(default_factory=list)
    """Host üzerindeki açık portların listesi."""

    @property
    def display_name(self) -> str:
        """Raporda kullanılacak host görünen adı."""
        if self.hostname:
            return f"{self.address} ({self.hostname})"
        return self.address

    @property
    def critical_findings(self) -> list[PortInfo]:
        """CRITICAL risk seviyesindeki port bulgularını döndürür."""
        return [p for p in self.open_ports if p.risk_level == "CRITICAL"]

    @property
    def high_findings(self) -> list[PortInfo]:
        """HIGH risk seviyesindeki port bulgularını döndürür."""
        return [p for p in self.open_ports if p.risk_level == "HIGH"]


@dataclass
class ScanResult:
    """
    Tamamlanmış bir taramanın tüm sonuçlarını içeren veri yapısı.
    """

    task_id: str
    """Görev benzersiz kimliği."""

    target: str
    """Taranan hedef (IP, CIDR veya hostname)."""

    status: ScanStatus
    """Tarama sonuç durumu."""

    hosts: list[HostInfo] = field(default_factory=list)
    """Taranan hostların listesi."""

    started_at: datetime = field(default_factory=utc_now)
    """Taramanın başlangıç zamanı (UTC)."""

    completed_at: datetime | None = None
    """Taramanın bitiş zamanı (UTC). Başarısız ise None olabilir."""

    raw_output: str = ""
    """Engine'den alınan ham çıktı (debug amaçlı)."""

    error_message: str = ""
    """Hata durumunda açıklayıcı mesaj."""

    engine_version: str = ""
    """Kullanılan engine sürümü (varsa)."""

    @property
    def duration_seconds(self) -> float | None:
        """Tarama süresini saniye cinsinden döndürür."""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def total_open_ports(self) -> int:
        """Tüm hostlardaki toplam açık port sayısı."""
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def overall_risk(self) -> str:
        """Taramanın genel risk seviyesi."""
        all_ports = [p for h in self.hosts for p in h.open_ports]
        if any(p.risk_level == "CRITICAL" for p in all_ports):
            return "CRITICAL"
        if any(p.risk_level == "HIGH" for p in all_ports):
            return "HIGH"
        if any(p.risk_level == "MEDIUM" for p in all_ports):
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict[str, Any]:
        """ScanResult'u JSON serileştirilebilir sözlüğe dönüştürür."""
        return {
            "task_id": self.task_id,
            "target": self.target,
            "status": self.status.name,
            "hosts_count": len(self.hosts),
            "total_open_ports": self.total_open_ports,
            "overall_risk": self.overall_risk,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message or None,
            "engine_version": self.engine_version or None,
        }


class _OutputParser:
    """
    ISU-SecOps-Engine'den gelen çıktıyı ayrıştıran dahili sınıf.
    """

    @staticmethod
    def detect_format(output: str) -> str:
        """Çıktı formatını algılar: 'json' veya 'text'."""
        stripped = output.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            return "json"
        return "text"

    @classmethod
    def parse(cls, output: str, target: str) -> list[HostInfo]:
        """
        Ham engine çıktısını ``HostInfo`` listesine dönüştürür.
        """
        fmt = cls.detect_format(output)

        if fmt == "json":
            return cls._parse_json(output, target)
        return cls._parse_text(output, target)

    @classmethod
    def _parse_json(cls, output: str, target: str) -> list[HostInfo]:
        """JSON formatındaki engine çıktısını ayrıştırır."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError as exc:
            raise EngineOutputError(
                f"Engine çıktısı geçerli JSON değil: {exc}",
                stderr_output=output[:500],
            ) from exc

        hosts: list[HostInfo] = []

        if isinstance(data, dict):
            data = [data]

        for item in data:
            host = cls._parse_json_host(item, fallback_address=target)
            hosts.append(host)

        return hosts

    @staticmethod
    def _parse_json_host(data: dict[str, Any], fallback_address: str) -> HostInfo:
        """Tek bir JSON host objesini HostInfo'ya dönüştürür."""
        address = data.get("url") or data.get("address") or data.get("ip") or fallback_address
        hostname = data.get("hostname") or data.get("host") or ""
        status = data.get("status", "up")
        os_detection = data.get("os") or data.get("os_detection") or ""

        ports: list[PortInfo] = []
        
        if "headers" in data and isinstance(data["headers"], list):
            for h in data["headers"]:
                if not h.get("passed", True) or not h.get("present", True):
                    port_info = PortInfo(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service=h.get("name", "security-header"),
                        version=h.get("note", "Missing security header"),
                        banner=f"Missing Security Header: {h.get('name')}"
                    )
                    ports.append(port_info)
        else:
            raw_ports = data.get("ports") or data.get("open_ports") or []
            for p in raw_ports:
                port_num = p.get("port") or p.get("number")
                if port_num is None:
                    continue

                port_info = PortInfo(
                    port=int(port_num),
                    protocol=p.get("protocol", "tcp").lower(),
                    state=p.get("state", "open").lower(),
                    service=p.get("service") or p.get("name") or "",
                    version=p.get("version") or p.get("product") or "",
                    banner=p.get("banner") or "",
                )
                ports.append(port_info)

        return HostInfo(
            address=str(address),
            hostname=str(hostname),
            status=str(status),
            os_detection=str(os_detection),
            open_ports=ports,
        )

    @classmethod
    def _parse_text(cls, output: str, target: str) -> list[HostInfo]:
        """
        Yapılandırılmış metin formatındaki engine çıktısını ayrıştırır.
        """
        import re

        hosts: list[HostInfo] = []
        current_host: HostInfo | None = None

        host_re = re.compile(
            r"HOST:\s*(\S+)(?:\s+\(([^)]+)\))?",
            re.IGNORECASE,
        )
        port_re = re.compile(
            r"PORT:\s*(\d+)/(tcp|udp)\s+(OPEN|CLOSED|FILTERED)"
            r"(?:\s+(\S+)(?:\s+(.+))?)?",
            re.IGNORECASE,
        )

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            host_match = host_re.match(line)
            if host_match:
                if current_host:
                    hosts.append(current_host)
                current_host = HostInfo(
                    address=host_match.group(1),
                    hostname=host_match.group(2) or "",
                )
                continue

            port_match = port_re.match(line)
            if port_match and current_host:
                current_host.open_ports.append(
                    PortInfo(
                        port=int(port_match.group(1)),
                        protocol=port_match.group(2).lower(),
                        state=port_match.group(3).lower(),
                        service=port_match.group(4) or "",
                        version=port_match.group(5) or "",
                    )
                )

        if current_host:
            hosts.append(current_host)

        if not hosts and output.strip():
            logger.warning(
                "Engine çıktısı ayrıştırılamadı, ham çıktı kullanılıyor.",
                extra={"output_preview": output[:200]},
            )
            hosts.append(HostInfo(address=target, status="unknown"))

        return hosts


class RustEngineWrapper:
    """
    ISU-SecOps-Engine Rust binary'sini asenkron olarak çalıştıran servis sınıfı.
    """

    def __init__(self, settings: AppSettings | None = None) -> None:
        self._settings = settings or get_settings()
        self._parser = _OutputParser()

    def _validate_engine(self) -> None:
        engine_path = self._settings.engine_path

        if not engine_path.is_absolute():
            found = shutil.which(str(engine_path))
            if not found:
                raise EngineNotFoundError(
                    f"ISU-SecOps-Engine binary'si PATH üzerinde bulunamadı: "
                    f"'{engine_path}'."
                )
            return

        if not engine_path.exists():
            raise EngineNotFoundError(
                f"ISU-SecOps-Engine binary'si bulunamadı: '{engine_path}'."
            )

        if not engine_path.is_file():
            raise EngineNotFoundError(
                f"Belirtilen engine yolu bir dosya değil: '{engine_path}'."
            )

        import os
        import platform
        if platform.system() != "Windows" and not os.access(engine_path, os.X_OK):
            raise EngineNotFoundError(
                f"ISU-SecOps-Engine binary'si çalıştırma iznine sahip değil: '{engine_path}'."
            )

    def _build_command(self, target: str, extra_args: list[str] | None = None) -> list[str]:
        """
        Engine için komut satırı argümanları listesini oluşturur.
        """
        url = target
        # Varsayılan protokol olarak http:// kullanıyoruz. (Gerekirse HTTPS'e otomatik yönlenecektir)
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"
            
        cmd = [str(self._settings.engine_path), "--url", url, "--json"]

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    @timed(logger_name=__name__)
    async def run_scan(
        self,
        task_id: str,
        target: str,
        extra_args: list[str] | None = None,
    ) -> ScanResult:
        started_at = utc_now()

        logger.info(
            "Tarama başlatılıyor.",
            extra={"task_id": task_id, "target": target},
        )

        self._validate_engine()

        command = self._build_command(target, extra_args)
        logger.debug(
            "Engine komutu oluşturuldu.",
            extra={"task_id": task_id, "command": " ".join(command)},
        )

        try:
            stdout, stderr = await self._execute_with_timeout(
                command=command,
                task_id=task_id,
                target=target,
            )
        except EngineTimeoutError:
            logger.error(
                "Tarama zaman aşımına uğradı.",
                extra={
                    "task_id": task_id,
                    "target": target,
                    "timeout": self._settings.scan_timeout,
                },
            )
            return ScanResult(
                task_id=task_id,
                target=target,
                status=ScanStatus.TIMEOUT,
                started_at=started_at,
                completed_at=utc_now(),
                error_message=(
                    f"Tarama {self._settings.scan_timeout} saniyede tamamlanamadı ve iptal edildi."
                ),
            )
        except EngineError:
            raise

        hosts = self._parser.parse(stdout, target)

        completed_at = utc_now()
        result = ScanResult(
            task_id=task_id,
            target=target,
            status=ScanStatus.COMPLETED,
            hosts=hosts,
            started_at=started_at,
            completed_at=completed_at,
            raw_output=stdout,
        )

        logger.info(
            "Tarama tamamlandı.",
            extra={
                "task_id": task_id,
                "target": target,
                "hosts_found": len(hosts),
                "open_ports": result.total_open_ports,
                "overall_risk": result.overall_risk,
                "duration": format_duration(result.duration_seconds or 0),
            },
        )

        return result

    async def _execute_with_timeout(
        self,
        command: list[str],
        task_id: str,
        target: str,
    ) -> tuple[str, str]:
        process: asyncio.subprocess.Process | None = None

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            logger.debug(
                "Engine süreci başlatıldı.",
                extra={"task_id": task_id, "pid": process.pid},
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=self._settings.scan_timeout,
            )

        except asyncio.TimeoutError:
            if process and process.returncode is None:
                logger.warning(
                    "Timeout nedeniyle süreç sonlandırılıyor.",
                    extra={"task_id": task_id, "pid": getattr(process, "pid", "N/A")},
                )
                try:
                    process.terminate()
                    await asyncio.sleep(2)
                    if process.returncode is None:
                        process.kill()
                except ProcessLookupError:
                    pass

            raise EngineTimeoutError(
                f"Tarama {self._settings.scan_timeout}s timeout'a uğradı.",
                timeout=self._settings.scan_timeout,
                target=target,
            )

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

        if stderr:
            logger.debug(
                "Engine stderr çıktısı alındı.",
                extra={"task_id": task_id, "stderr_preview": stderr[:300]},
            )

        return_code = process.returncode
        if return_code != 0:
            raise EngineCrashError(
                f"ISU-SecOps-Engine sıfırdan farklı çıkış kodu döndürdü: {return_code}.",
                stderr_output=stderr,
                return_code=return_code,
            )

        if not stdout:
            logger.warning(
                "Engine boş stdout çıktısı üretti.",
                extra={"task_id": task_id, "target": target},
            )

        return stdout, stderr

    async def health_check(self) -> dict[str, Any]:
        try:
            self._validate_engine()
            engine_available = True
            engine_error = None
        except EngineNotFoundError as exc:
            engine_available = False
            engine_error = str(exc)

        engine_version = "unknown"
        if engine_available:
            try:
                process = await asyncio.create_subprocess_exec(
                    str(self._settings.engine_path),
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, _ = await asyncio.wait_for(process.communicate(), timeout=5)
                engine_version = out.decode().strip() or "unknown"
            except Exception:
                engine_version = "version check failed"

        return {
            "engine_path": str(self._settings.engine_path),
            "engine_available": engine_available,
            "engine_version": engine_version,
            "engine_error": engine_error,
            "scan_timeout": self._settings.scan_timeout,
        }
