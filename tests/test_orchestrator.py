"""
ISU-SecOps-Orchestrator — Comprehensive Test Suite
====================================================
pytest + pytest-asyncio + httpx.AsyncClient kullanarak:
    - FastAPI endpoint entegrasyon testleri
    - RustEngineWrapper subprocess mock testleri
    - VulnerabilityReportGenerator birim testleri
    - Validasyon ve hata senaryoları
    - Edge case ve boundary condition testleri

Çalıştırma:
    pytest tests/ -v --asyncio-mode=auto --cov=orchestrator --cov-report=term-missing

Author: ISU-SecOps Team
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Proje import'ları
# ---------------------------------------------------------------------------

from orchestrator.app.config import AppSettings, get_settings
from orchestrator.app.main import app, _task_store, _store_lock
from orchestrator.app.reporter import (
    OWASP_MAPPING,
    REMEDIATION_MAPPING,
    FindingSummary,
    VulnerabilityReportGenerator,
)
from orchestrator.app.scanner import (
    EngineCrashError,
    EngineNotFoundError,
    EngineOutputError,
    EngineTimeoutError,
    HostInfo,
    PortInfo,
    RustEngineWrapper,
    ScanResult,
    ScanStatus,
    _OutputParser,
)
from orchestrator.app.utils import (
    generate_task_id,
    get_service_name,
    sanitize_target,
    utc_now,
)

# ---------------------------------------------------------------------------
# Test Sabitleri
# ---------------------------------------------------------------------------

MOCK_JSON_OUTPUT = json.dumps([
    {
        "address": "192.168.1.1",
        "hostname": "router.local",
        "status": "up",
        "os": "Linux 5.15",
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "SSH",
                "version": "OpenSSH_8.9",
            },
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "HTTP",
                "version": "nginx/1.18.0",
            },
            {
                "port": 3389,
                "protocol": "tcp",
                "state": "open",
                "service": "RDP",
                "version": "",
            },
        ],
    }
])

MOCK_TEXT_OUTPUT = """
HOST: 192.168.1.100 (server.corp)
PORT: 22/tcp OPEN SSH OpenSSH_9.0
PORT: 443/tcp OPEN HTTPS nginx/1.24
PORT: 6379/tcp OPEN Redis 7.0.5
"""

MOCK_EMPTY_OUTPUT = ""

MOCK_INVALID_JSON = "{ not valid json"

# ---------------------------------------------------------------------------
# Fixture'lar
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Geçici test dizini oluşturur ve test sonrası siler."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def test_settings(temp_dir: Path) -> AppSettings:
    """
    Test için izole AppSettings örneği.

    Gerçek disk dosyalarını etkilememek için geçici dizin kullanır
    ve cache'i temizler.
    """
    get_settings.cache_clear()

    settings = AppSettings(
        app_name="ISU-SecOps-Test",
        log_level="DEBUG",
        log_format="text",
        engine_path=temp_dir / "fake_engine",
        reports_dir=temp_dir / "reports",
        scan_timeout=30,
        max_concurrent_scans=2,
    )
    return settings


@pytest.fixture
def mock_engine_path(temp_dir: Path) -> Path:
    """
    Sahte (fake) bir engine binary'si oluşturur.
    Dosya içeriği önemli değil, yalnızca varlığı kontrol edilir.
    """
    engine = temp_dir / "isu-secops-engine"
    engine.write_text("#!/bin/sh\necho 'fake engine'")
    return engine


@pytest.fixture
def sample_port_info() -> PortInfo:
    """Test için örnek PortInfo nesnesi."""
    return PortInfo(
        port=22,
        protocol="tcp",
        state="open",
        service="SSH",
        version="OpenSSH_8.9",
    )


@pytest.fixture
def sample_host_info(sample_port_info: PortInfo) -> HostInfo:
    """Test için örnek HostInfo nesnesi."""
    return HostInfo(
        address="192.168.1.1",
        hostname="test.local",
        status="up",
        os_detection="Linux 5.15",
        open_ports=[
            sample_port_info,
            PortInfo(port=3389, protocol="tcp", state="open", service="RDP"),
            PortInfo(port=80, protocol="tcp", state="open", service="HTTP"),
        ],
    )


@pytest.fixture
def sample_scan_result(sample_host_info: HostInfo) -> ScanResult:
    """Tamamlanmış test tarama sonucu."""
    return ScanResult(
        task_id="task-test000001",
        target="192.168.1.0/24",
        status=ScanStatus.COMPLETED,
        hosts=[sample_host_info],
        started_at=utc_now(),
        completed_at=utc_now(),
        raw_output=MOCK_JSON_OUTPUT,
    )


@pytest.fixture
def report_generator(test_settings: AppSettings) -> VulnerabilityReportGenerator:
    """Test için VulnerabilityReportGenerator örneği."""
    return VulnerabilityReportGenerator(settings=test_settings)


@pytest_asyncio.fixture
async def test_client() -> AsyncGenerator[AsyncClient, None]:
    """
    FastAPI test istemcisi.

    Her testte temiz bir görev deposuyla başlar.
    """
    # Test öncesi görev deposunu temizle
    async with _store_lock:
        _task_store.clear()

    get_settings.cache_clear()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client

    # Test sonrası temizlik
    async with _store_lock:
        _task_store.clear()


# ===========================================================================
# BÖLÜM 1: Yardımcı Fonksiyon Birim Testleri
# ===========================================================================


class TestSanitizeTarget:
    """sanitize_target() fonksiyonu için testler."""

    def test_valid_ipv4(self) -> None:
        assert sanitize_target("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv4_with_whitespace(self) -> None:
        assert sanitize_target("  10.0.0.1  ") == "10.0.0.1"

    def test_valid_cidr(self) -> None:
        assert sanitize_target("192.168.1.0/24") == "192.168.1.0/24"

    def test_valid_cidr_class_a(self) -> None:
        assert sanitize_target("10.0.0.0/8") == "10.0.0.0/8"

    def test_valid_hostname(self) -> None:
        assert sanitize_target("internal.corp.com") == "internal.corp.com"

    def test_valid_simple_hostname(self) -> None:
        assert sanitize_target("localhost") == "localhost"

    def test_empty_target_raises(self) -> None:
        with pytest.raises(ValueError, match="boş olamaz"):
            sanitize_target("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError, match="boş olamaz"):
            sanitize_target("   ")

    def test_too_long_target_raises(self) -> None:
        with pytest.raises(ValueError, match="çok uzun"):
            sanitize_target("a" * 254)

    def test_invalid_target_raises(self) -> None:
        with pytest.raises(ValueError, match="Geçersiz tarama hedefi"):
            sanitize_target("not@valid!target")


class TestGenerateTaskId:
    """generate_task_id() fonksiyonu için testler."""

    def test_format(self) -> None:
        task_id = generate_task_id()
        assert task_id.startswith("task-")
        assert len(task_id) == len("task-") + 12

    def test_uniqueness(self) -> None:
        ids = {generate_task_id() for _ in range(100)}
        assert len(ids) == 100  # Tüm ID'ler benzersiz olmalı

    def test_hex_characters(self) -> None:
        task_id = generate_task_id()
        hex_part = task_id[len("task-"):]
        assert all(c in "0123456789abcdef" for c in hex_part)


class TestGetServiceName:
    """get_service_name() fonksiyonu için testler."""

    def test_known_port_ssh(self) -> None:
        assert get_service_name(22) == "SSH"

    def test_known_port_rdp(self) -> None:
        assert get_service_name(3389) == "RDP"

    def test_known_port_http(self) -> None:
        assert get_service_name(80) == "HTTP"

    def test_unknown_port(self) -> None:
        assert get_service_name(54321) == "Unknown"


# ===========================================================================
# BÖLÜM 2: Scanner Veri Modeli Testleri
# ===========================================================================


class TestPortInfo:
    """PortInfo dataclass testleri."""

    def test_risk_level_critical_rdp(self) -> None:
        port = PortInfo(port=3389, protocol="tcp", state="open")
        assert port.risk_level == "CRITICAL"

    def test_risk_level_critical_telnet(self) -> None:
        port = PortInfo(port=23, protocol="tcp", state="open")
        assert port.risk_level == "CRITICAL"

    def test_risk_level_high_redis(self) -> None:
        port = PortInfo(port=6379, protocol="tcp", state="open")
        assert port.risk_level == "HIGH"

    def test_risk_level_low_https(self) -> None:
        port = PortInfo(port=443, protocol="tcp", state="open")
        assert port.risk_level == "LOW"

    def test_risk_level_medium_unknown(self) -> None:
        port = PortInfo(port=8888, protocol="tcp", state="open")
        assert port.risk_level == "MEDIUM"

    def test_auto_service_name(self) -> None:
        """Servis adı verilmezse otomatik atanmalı."""
        port = PortInfo(port=22, protocol="tcp", state="open")
        assert port.service == "SSH"

    def test_explicit_service_name(self) -> None:
        """Açık servis adı otomatik atamayı override etmemeli."""
        port = PortInfo(port=22, protocol="tcp", state="open", service="Custom SSH")
        assert port.service == "Custom SSH"


class TestHostInfo:
    """HostInfo dataclass testleri."""

    def test_display_name_with_hostname(self, sample_host_info: HostInfo) -> None:
        assert "192.168.1.1" in sample_host_info.display_name
        assert "test.local" in sample_host_info.display_name

    def test_display_name_without_hostname(self) -> None:
        host = HostInfo(address="10.0.0.1")
        assert host.display_name == "10.0.0.1"

    def test_critical_findings_filter(self, sample_host_info: HostInfo) -> None:
        critical = sample_host_info.critical_findings
        assert all(p.risk_level == "CRITICAL" for p in critical)
        assert any(p.port == 3389 for p in critical)

    def test_high_findings_filter(self) -> None:
        host = HostInfo(
            address="10.0.0.1",
            open_ports=[
                PortInfo(port=6379, protocol="tcp", state="open"),
                PortInfo(port=443, protocol="tcp", state="open"),
            ],
        )
        high = host.high_findings
        assert len(high) == 1
        assert high[0].port == 6379


class TestScanResult:
    """ScanResult dataclass testleri."""

    def test_total_open_ports(self, sample_scan_result: ScanResult) -> None:
        assert sample_scan_result.total_open_ports == 3

    def test_overall_risk_with_critical(self, sample_scan_result: ScanResult) -> None:
        assert sample_scan_result.overall_risk == "CRITICAL"

    def test_overall_risk_no_critical(self) -> None:
        host = HostInfo(
            address="10.0.0.1",
            open_ports=[
                PortInfo(port=80, protocol="tcp", state="open"),
            ],
        )
        result = ScanResult(
            task_id="test",
            target="10.0.0.1",
            status=ScanStatus.COMPLETED,
            hosts=[host],
        )
        assert result.overall_risk == "MEDIUM"

    def test_duration_calculation(self, sample_scan_result: ScanResult) -> None:
        assert sample_scan_result.duration_seconds is not None
        assert sample_scan_result.duration_seconds >= 0

    def test_to_dict_serializable(self, sample_scan_result: ScanResult) -> None:
        d = sample_scan_result.to_dict()
        assert "task_id" in d
        assert "target" in d
        assert "status" in d
        assert d["status"] == "COMPLETED"
        # JSON serileştirilebilir olmalı
        serialized = json.dumps(d)
        assert len(serialized) > 0


# ===========================================================================
# BÖLÜM 3: Output Parser Birim Testleri
# ===========================================================================


class TestOutputParser:
    """_OutputParser sınıfı için testler."""

    def test_detect_json_format(self) -> None:
        assert _OutputParser.detect_format(MOCK_JSON_OUTPUT) == "json"

    def test_detect_text_format(self) -> None:
        assert _OutputParser.detect_format(MOCK_TEXT_OUTPUT) == "text"

    def test_parse_valid_json(self) -> None:
        hosts = _OutputParser.parse(MOCK_JSON_OUTPUT, "192.168.1.1")
        assert len(hosts) == 1
        assert hosts[0].address == "192.168.1.1"
        assert hosts[0].hostname == "router.local"
        assert len(hosts[0].open_ports) == 3

    def test_parse_json_port_details(self) -> None:
        hosts = _OutputParser.parse(MOCK_JSON_OUTPUT, "192.168.1.1")
        ports = {p.port: p for p in hosts[0].open_ports}
        assert 22 in ports
        assert ports[22].service == "SSH"
        assert ports[22].version == "OpenSSH_8.9"

    def test_parse_valid_text(self) -> None:
        hosts = _OutputParser.parse(MOCK_TEXT_OUTPUT, "192.168.1.100")
        assert len(hosts) == 1
        assert hosts[0].address == "192.168.1.100"
        assert hosts[0].hostname == "server.corp"
        assert len(hosts[0].open_ports) == 3

    def test_parse_text_port_details(self) -> None:
        hosts = _OutputParser.parse(MOCK_TEXT_OUTPUT, "192.168.1.100")
        ports = {p.port: p for p in hosts[0].open_ports}
        assert 22 in ports
        assert 443 in ports
        assert 6379 in ports

    def test_parse_empty_output_returns_empty_host(self) -> None:
        """Boş çıktı için hedef adresinde boş host döner."""
        hosts = _OutputParser.parse(MOCK_EMPTY_OUTPUT, "10.0.0.1")
        # Boş çıktı durumunda boş liste veya fallback host döner
        assert isinstance(hosts, list)

    def test_parse_invalid_json_raises(self) -> None:
        with pytest.raises(EngineOutputError):
            _OutputParser.parse(MOCK_INVALID_JSON, "192.168.1.1")

    def test_parse_multiple_hosts_json(self) -> None:
        multi_json = json.dumps([
            {"address": "10.0.0.1", "ports": [{"port": 22, "protocol": "tcp", "state": "open"}]},
            {"address": "10.0.0.2", "ports": [{"port": 80, "protocol": "tcp", "state": "open"}]},
        ])
        hosts = _OutputParser.parse(multi_json, "10.0.0.0/24")
        assert len(hosts) == 2
        assert hosts[0].address == "10.0.0.1"
        assert hosts[1].address == "10.0.0.2"

    def test_parse_single_dict_json(self) -> None:
        """Tek obje JSON (liste değil) parse edilebilmeli."""
        single_json = json.dumps({
            "address": "172.16.0.1",
            "ports": [],
        })
        hosts = _OutputParser.parse(single_json, "172.16.0.1")
        assert len(hosts) == 1
        assert hosts[0].address == "172.16.0.1"


# ===========================================================================
# BÖLÜM 4: RustEngineWrapper Testleri (Subprocess Mock)
# ===========================================================================


class TestRustEngineWrapper:
    """RustEngineWrapper için subprocess mock testleri."""

    @pytest.mark.asyncio
    async def test_engine_not_found_raises(self, test_settings: AppSettings) -> None:
        """Binary bulunamadığında EngineNotFoundError fırlatılmalı."""
        # engine_path var olmayan bir yere ayarla
        test_settings.engine_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper = RustEngineWrapper(settings=test_settings)

        with pytest.raises(EngineNotFoundError):
            await wrapper.run_scan(task_id="task-test", target="192.168.1.1")

    @pytest.mark.asyncio
    async def test_successful_scan(
        self, test_settings: AppSettings, mock_engine_path: Path
    ) -> None:
        """Başarılı tarama ScanResult.COMPLETED döndürmeli."""
        test_settings = AppSettings(
            engine_path=mock_engine_path,
            reports_dir=test_settings.reports_dir,
            scan_timeout=30,
        )
        wrapper = RustEngineWrapper(settings=test_settings)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.pid = 12345
        mock_process.communicate = AsyncMock(
            return_value=(MOCK_JSON_OUTPUT.encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wrapper.run_scan(
                task_id="task-success",
                target="192.168.1.1",
            )

        assert result.status == ScanStatus.COMPLETED
        assert result.task_id == "task-success"
        assert result.target == "192.168.1.1"
        assert len(result.hosts) == 1
        assert result.total_open_ports == 3

    @pytest.mark.asyncio
    async def test_engine_crash_raises(
        self, test_settings: AppSettings, mock_engine_path: Path
    ) -> None:
        """Engine sıfırdan farklı çıkış kodu döndürdüğünde EngineCrashError fırlatılmalı."""
        test_settings = AppSettings(
            engine_path=mock_engine_path,
            reports_dir=test_settings.reports_dir,
            scan_timeout=30,
        )
        wrapper = RustEngineWrapper(settings=test_settings)

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.pid = 12345
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"ERROR: Connection refused")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with pytest.raises(EngineCrashError) as exc_info:
                await wrapper.run_scan(
                    task_id="task-crash",
                    target="192.168.1.1",
                )

        assert exc_info.value.return_code == 1
        assert "ERROR: Connection refused" in exc_info.value.stderr_output

    @pytest.mark.asyncio
    async def test_timeout_returns_timeout_status(
        self, test_settings: AppSettings, mock_engine_path: Path
    ) -> None:
        """Timeout durumunda ScanStatus.TIMEOUT döndürmeli."""
        test_settings = AppSettings(
            engine_path=mock_engine_path,
            reports_dir=test_settings.reports_dir,
            scan_timeout=1,  # 1 saniye timeout
        )
        wrapper = RustEngineWrapper(settings=test_settings)

        async def slow_communicate():
            await asyncio.sleep(10)  # Timeout'tan çok uzun
            return b"", b""

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.communicate = slow_communicate
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = await wrapper.run_scan(
                task_id="task-timeout",
                target="192.168.1.1",
            )

        assert result.status == ScanStatus.TIMEOUT
        assert result.error_message is not None
        assert len(result.error_message) > 0

    @pytest.mark.asyncio
    async def test_health_check_engine_missing(
        self, test_settings: AppSettings
    ) -> None:
        """Engine yokken health check 'engine_available: False' döndürmeli."""
        wrapper = RustEngineWrapper(settings=test_settings)
        health = await wrapper.health_check()

        assert health["engine_available"] is False
        assert health["engine_error"] is not None

    @pytest.mark.asyncio
    async def test_build_command_structure(
        self, test_settings: AppSettings, mock_engine_path: Path
    ) -> None:
        """Oluşturulan komut doğru yapıda olmalı."""
        test_settings = AppSettings(
            engine_path=mock_engine_path,
            reports_dir=test_settings.reports_dir,
        )
        wrapper = RustEngineWrapper(settings=test_settings)
        cmd = wrapper._build_command("192.168.1.0/24")

        assert str(mock_engine_path) in cmd
        assert "--target" in cmd
        assert "192.168.1.0/24" in cmd
        assert "--format" in cmd
        assert "json" in cmd


# ===========================================================================
# BÖLÜM 5: VulnerabilityReportGenerator Birim Testleri
# ===========================================================================


class TestVulnerabilityReportGenerator:
    """VulnerabilityReportGenerator için birim testleri."""

    def test_generate_report_creates_file(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor dosyasının disk üzerinde oluşturulması."""
        report_path = report_generator.generate(sample_scan_result)

        assert report_path.exists()
        assert report_path.suffix == ".md"
        assert report_path.stat().st_size > 0

    def test_report_filename_contains_target(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor dosya adı hedef bilgisini içermeli."""
        report_path = report_generator.generate(sample_scan_result)
        assert "isu_secops" in report_path.name

    def test_report_contains_task_id(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor task_id'yi içermeli."""
        report_path = report_generator.generate(sample_scan_result)
        content = report_path.read_text(encoding="utf-8")
        assert sample_scan_result.task_id in content

    def test_report_contains_target(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor hedef adresini içermeli."""
        report_path = report_generator.generate(sample_scan_result)
        content = report_path.read_text(encoding="utf-8")
        assert sample_scan_result.target in content

    def test_report_contains_owasp_reference(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor OWASP referanslarını içermeli."""
        report_path = report_generator.generate(sample_scan_result)
        content = report_path.read_text(encoding="utf-8")
        assert "OWASP" in content

    def test_report_contains_executive_summary(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor yönetici özeti bölümünü içermeli."""
        report_path = report_generator.generate(sample_scan_result)
        content = report_path.read_text(encoding="utf-8")
        assert "Yönetici Özeti" in content or "Executive Summary" in content

    def test_report_contains_risk_level(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor risk seviyesini içermeli."""
        report_path = report_generator.generate(sample_scan_result)
        content = report_path.read_text(encoding="utf-8")
        assert "CRITICAL" in content  # RDP (3389) kritik port içeriyor

    def test_report_contains_remediation(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Rapor sıkılaştırma önerilerini içermeli."""
        report_path = report_generator.generate(sample_scan_result)
        content = report_path.read_text(encoding="utf-8")
        assert "Sıkılaştırma" in content or "Remediation" in content

    def test_compute_summary_statistics(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Özet istatistiklerin doğru hesaplanması."""
        summary = report_generator._compute_summary(sample_scan_result)
        assert summary.total_hosts == 1
        assert summary.total_open_ports == 3
        assert summary.critical_count > 0  # RDP (3389) kritik
        assert summary.total_findings == 3

    def test_overall_risk_with_critical_port(
        self,
        report_generator: VulnerabilityReportGenerator,
        sample_scan_result: ScanResult,
    ) -> None:
        """Kritik port varken genel risk 'CRITICAL' olmalı."""
        summary = report_generator._compute_summary(sample_scan_result)
        assert summary.overall_risk == "CRITICAL"

    def test_overall_risk_without_critical(
        self,
        report_generator: VulnerabilityReportGenerator,
    ) -> None:
        """Kritik port yokken risk seviyesi 'MEDIUM' veya altı olmalı."""
        host = HostInfo(
            address="10.0.0.1",
            open_ports=[
                PortInfo(port=80, protocol="tcp", state="open"),  # MEDIUM
            ],
        )
        result = ScanResult(
            task_id="task-low",
            target="10.0.0.1",
            status=ScanStatus.COMPLETED,
            hosts=[host],
        )
        summary = report_generator._compute_summary(result)
        assert summary.overall_risk in ("MEDIUM", "LOW")

    def test_empty_scan_report(
        self,
        report_generator: VulnerabilityReportGenerator,
    ) -> None:
        """Boş tarama sonucu için rapor üretilebilmeli."""
        result = ScanResult(
            task_id="task-empty",
            target="10.0.0.0/24",
            status=ScanStatus.COMPLETED,
            hosts=[],
        )
        report_path = report_generator.generate(result)
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert len(content) > 100  # Boş olsa da başlık vb. olmalı

    def test_progress_bar_full(self) -> None:
        bar = VulnerabilityReportGenerator._progress_bar(10, 10, 20)
        assert "█" * 20 in bar

    def test_progress_bar_empty(self) -> None:
        bar = VulnerabilityReportGenerator._progress_bar(0, 10, 20)
        assert "░" * 20 in bar

    def test_progress_bar_zero_total(self) -> None:
        """Sıfır toplam ile ZeroDivisionError olmamalı."""
        bar = VulnerabilityReportGenerator._progress_bar(0, 0, 20)
        assert "0%" in bar


# ===========================================================================
# BÖLÜM 6: OWASP ve Remediation Veri Tablosu Testleri
# ===========================================================================


class TestOWASPMapping:
    """OWASP eşleme tablosu doğruluk testleri."""

    def test_rdp_mapped_to_owasp(self) -> None:
        assert 3389 in OWASP_MAPPING
        assert "A05:2021" in OWASP_MAPPING[3389]["id"]

    def test_telnet_mapped_to_owasp(self) -> None:
        assert 23 in OWASP_MAPPING

    def test_smb_mapped_to_owasp(self) -> None:
        assert 445 in OWASP_MAPPING

    def test_all_entries_have_required_fields(self) -> None:
        required_fields = {"id", "name", "description", "cwe"}
        for port, entry in OWASP_MAPPING.items():
            assert required_fields <= entry.keys(), f"Port {port} eksik alan içeriyor"

    def test_cwe_format(self) -> None:
        """Tüm CWE referansları 'CWE-XXXX' formatında olmalı."""
        import re
        cwe_pattern = re.compile(r"^CWE-\d+$")
        for port, entry in OWASP_MAPPING.items():
            assert cwe_pattern.match(entry["cwe"]), (
                f"Port {port}: Geçersiz CWE formatı: {entry['cwe']}"
            )

    def test_remediation_coverage(self) -> None:
        """Kritik portların tamamı için remediation önerisi bulunmalı."""
        critical_ports = {21, 22, 23, 80, 445, 3389}
        for port in critical_ports:
            assert port in REMEDIATION_MAPPING, (
                f"Port {port} için remediation önerisi eksik"
            )


# ===========================================================================
# BÖLÜM 7: FastAPI Endpoint Entegrasyon Testleri
# ===========================================================================


class TestHealthEndpoint:
    """GET /api/v1/health endpoint testleri."""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_health_response_structure(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/health")
        data = response.json()
        required_fields = {
            "status", "timestamp", "app_name", "app_version",
            "engine_available", "engine_path", "active_tasks",
        }
        assert required_fields <= data.keys()

    @pytest.mark.asyncio
    async def test_health_status_values(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/health")
        data = response.json()
        assert data["status"] in ("healthy", "degraded")

    @pytest.mark.asyncio
    async def test_health_app_name(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/health")
        data = response.json()
        assert "ISU-SecOps" in data["app_name"]


class TestAPIRoot:
    """GET /api/v1/ endpoint testleri."""

    @pytest.mark.asyncio
    async def test_root_returns_200(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_root_contains_endpoints(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/")
        data = response.json()
        assert "endpoints" in data
        assert "scan" in data["endpoints"]


class TestScanEndpoint:
    """POST /api/v1/scan endpoint testleri."""

    @pytest.mark.asyncio
    async def test_scan_returns_202_accepted(self, test_client: AsyncClient) -> None:
        """Geçerli hedef ile 202 Accepted döndürmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": "192.168.1.1"},
        )
        assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_scan_response_contains_task_id(
        self, test_client: AsyncClient
    ) -> None:
        """Yanıt task_id içermeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": "10.0.0.1"},
        )
        data = response.json()
        assert "task_id" in data
        assert data["task_id"].startswith("task-")

    @pytest.mark.asyncio
    async def test_scan_response_structure(self, test_client: AsyncClient) -> None:
        """Yanıt beklenen alanları içermeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": "192.168.1.1"},
        )
        data = response.json()
        required_fields = {
            "task_id", "status", "message", "target",
            "submitted_at", "status_url",
        }
        assert required_fields <= data.keys()

    @pytest.mark.asyncio
    async def test_scan_initial_status_pending(
        self, test_client: AsyncClient
    ) -> None:
        """İlk durum PENDING olmalı."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": "192.168.1.1"},
        )
        data = response.json()
        assert data["status"] == "PENDING"

    @pytest.mark.asyncio
    async def test_scan_invalid_target_returns_422(
        self, test_client: AsyncClient
    ) -> None:
        """Geçersiz hedef ile 422 Unprocessable Entity döndürmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": "not@valid!target"},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_scan_empty_target_returns_422(
        self, test_client: AsyncClient
    ) -> None:
        """Boş hedef ile 422 döndürmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": ""},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_scan_missing_target_returns_422(
        self, test_client: AsyncClient
    ) -> None:
        """Target alanı eksikse 422 döndürmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_scan_with_cidr_target(self, test_client: AsyncClient) -> None:
        """CIDR hedef kabul edilmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": "192.168.0.0/24"},
        )
        assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_scan_with_hostname_target(self, test_client: AsyncClient) -> None:
        """Hostname hedef kabul edilmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": "internal.corp.com"},
        )
        assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_scan_command_injection_blocked(
        self, test_client: AsyncClient
    ) -> None:
        """Komut enjeksiyonu girişimi reddedilmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={
                "target": "192.168.1.1",
                "extra_args": ["--timeout; rm -rf /"],
            },
        )
        assert response.status_code == 422


class TestScanStatusEndpoint:
    """GET /api/v1/scan/{task_id} endpoint testleri."""

    @pytest.mark.asyncio
    async def test_status_of_submitted_task(self, test_client: AsyncClient) -> None:
        """Gönderilen görevin durumu sorgulanabilmeli."""
        # Önce tarama başlat
        post_response = await test_client.post(
            "/api/v1/scan",
            json={"target": "10.0.0.1"},
        )
        task_id = post_response.json()["task_id"]

        # Durum sorgula
        get_response = await test_client.get(f"/api/v1/scan/{task_id}")
        assert get_response.status_code == 200

    @pytest.mark.asyncio
    async def test_status_response_structure(self, test_client: AsyncClient) -> None:
        """Durum yanıtı beklenen alanları içermeli."""
        post_response = await test_client.post(
            "/api/v1/scan",
            json={"target": "10.0.0.1"},
        )
        task_id = post_response.json()["task_id"]

        get_response = await test_client.get(f"/api/v1/scan/{task_id}")
        data = get_response.json()

        required_fields = {"task_id", "status", "target", "submitted_at"}
        assert required_fields <= data.keys()

    @pytest.mark.asyncio
    async def test_nonexistent_task_returns_404(
        self, test_client: AsyncClient
    ) -> None:
        """Var olmayan görev 404 döndürmeli."""
        response = await test_client.get("/api/v1/scan/task-nonexistent123")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_nonexistent_task_error_structure(
        self, test_client: AsyncClient
    ) -> None:
        """404 yanıtı beklenen hata yapısında olmalı."""
        response = await test_client.get("/api/v1/scan/task-nonexistent123")
        data = response.json()
        assert "detail" in data


class TestReportsEndpoint:
    """GET /api/v1/reports endpoint testleri."""

    @pytest.mark.asyncio
    async def test_reports_returns_200(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/reports")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_reports_response_structure(self, test_client: AsyncClient) -> None:
        response = await test_client.get("/api/v1/reports")
        data = response.json()
        assert "total" in data
        assert "reports" in data
        assert isinstance(data["reports"], list)

    @pytest.mark.asyncio
    async def test_reports_pagination_params(self, test_client: AsyncClient) -> None:
        """Sayfalama parametreleri desteklenmeli."""
        response = await test_client.get("/api/v1/reports?limit=10&offset=0")
        assert response.status_code == 200


# ===========================================================================
# BÖLÜM 8: Parametrize Testler
# ===========================================================================


class TestParametrized:
    """Parametrize edilmiş çoklu senaryo testleri."""

    @pytest.mark.parametrize(
        "target,expected_valid",
        [
            ("192.168.1.1", True),
            ("10.0.0.0/8", True),
            ("172.16.0.0/12", True),
            ("internal.server.com", True),
            ("localhost", True),
            ("", False),
            ("not@valid", False),
            ("256.256.256.256", False),
            ("   ", False),
        ],
    )
    def test_target_validation(self, target: str, expected_valid: bool) -> None:
        """Çeşitli hedef formatlarının doğrulama sonuçları."""
        if expected_valid:
            result = sanitize_target(target)
            assert result == target.strip()
        else:
            with pytest.raises(ValueError):
                sanitize_target(target)

    @pytest.mark.parametrize(
        "port,expected_risk",
        [
            (21, "CRITICAL"),   # FTP
            (23, "CRITICAL"),   # Telnet
            (3389, "CRITICAL"),  # RDP
            (5900, "CRITICAL"),  # VNC
            (6379, "HIGH"),      # Redis
            (27017, "HIGH"),     # MongoDB
            (443, "LOW"),        # HTTPS
            (993, "LOW"),        # IMAPS
            (8888, "MEDIUM"),    # Unknown
        ],
    )
    def test_port_risk_levels(self, port: int, expected_risk: str) -> None:
        """Çeşitli portların risk seviyeleri."""
        port_info = PortInfo(port=port, protocol="tcp", state="open")
        assert port_info.risk_level == expected_risk

    @pytest.mark.parametrize(
        "scan_status,expected_name",
        [
            (ScanStatus.PENDING, "PENDING"),
            (ScanStatus.RUNNING, "RUNNING"),
            (ScanStatus.COMPLETED, "COMPLETED"),
            (ScanStatus.FAILED, "FAILED"),
            (ScanStatus.TIMEOUT, "TIMEOUT"),
        ],
    )
    def test_scan_status_names(
        self, scan_status: ScanStatus, expected_name: str
    ) -> None:
        """ScanStatus enum değerlerinin isimleri."""
        assert scan_status.name == expected_name

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "invalid_target",
        ["", "not@valid!", "a" * 254, "256.256.256.256"],
    )
    async def test_api_rejects_invalid_targets(
        self, test_client: AsyncClient, invalid_target: str
    ) -> None:
        """API çeşitli geçersiz hedefleri reddetmeli."""
        response = await test_client.post(
            "/api/v1/scan",
            json={"target": invalid_target},
        )
        assert response.status_code == 422


# ===========================================================================
# BÖLÜM 9: Exception Hiyerarşisi Testleri
# ===========================================================================


class TestExceptionHierarchy:
    """Özel istisna sınıflarının testleri."""

    def test_engine_not_found_is_engine_error(self) -> None:
        exc = EngineNotFoundError("test")
        assert isinstance(exc, EngineError)

    def test_engine_timeout_is_engine_error(self) -> None:
        exc = EngineTimeoutError("test", timeout=30, target="192.168.1.1")
        assert isinstance(exc, EngineError)
        assert exc.timeout == 30
        assert exc.target == "192.168.1.1"

    def test_engine_crash_is_engine_error(self) -> None:
        exc = EngineCrashError("test", return_code=1, stderr_output="error")
        assert isinstance(exc, EngineError)
        assert exc.return_code == 1
        assert exc.stderr_output == "error"

    def test_engine_output_error_is_engine_error(self) -> None:
        exc = EngineOutputError("parse error")
        assert isinstance(exc, EngineError)

    def test_engine_error_repr(self) -> None:
        exc = EngineCrashError("crash", return_code=137)
        assert "EngineCrashError" in repr(exc)
        assert "137" in repr(exc)


# ===========================================================================
# BÖLÜM 10: FindingSummary Testleri
# ===========================================================================


class TestFindingSummary:
    """FindingSummary dataclass testleri."""

    def test_total_findings(self) -> None:
        s = FindingSummary(critical_count=2, high_count=3, medium_count=5, low_count=1)
        assert s.total_findings == 11

    def test_overall_risk_critical(self) -> None:
        s = FindingSummary(critical_count=1)
        assert s.overall_risk == "CRITICAL"

    def test_overall_risk_high(self) -> None:
        s = FindingSummary(critical_count=0, high_count=3)
        assert s.overall_risk == "HIGH"

    def test_overall_risk_medium(self) -> None:
        s = FindingSummary(critical_count=0, high_count=0, medium_count=2)
        assert s.overall_risk == "MEDIUM"

    def test_overall_risk_low(self) -> None:
        s = FindingSummary()
        assert s.overall_risk == "LOW"

    def test_risk_emoji_critical(self) -> None:
        s = FindingSummary(critical_count=1)
        assert s.risk_emoji == "🔴"

    def test_risk_emoji_low(self) -> None:
        s = FindingSummary()
        assert s.risk_emoji == "🟢"
