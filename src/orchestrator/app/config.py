"""
ISU-SecOps-Orchestrator — Configuration Module
===============================================
Pydantic BaseSettings ile çevre değişkeni tabanlı dinamik konfigürasyon yönetimi.
Tüm ayarlar .env dosyasından veya sistem environment'ından okunabilir.

Author: ISU-SecOps Team
Version: 1.0.0
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
"""Projenin kök dizini (ISU-SecOps-Orchestrator/)."""

DEFAULT_ENGINE_PATH: Path = PROJECT_ROOT / "core_engine" / "isu-secops-engine"
"""Rust binary'sinin varsayılan konumu."""

DEFAULT_REPORTS_DIR: Path = PROJECT_ROOT / "reports"
"""Tarih damgalı Markdown raporlarının kaydedileceği dizin."""


# ---------------------------------------------------------------------------
# Konfigürasyon Sınıfı
# ---------------------------------------------------------------------------


class AppSettings(BaseSettings):
    """
    ISU-SecOps-Orchestrator uygulama konfigürasyonu.

    Tüm alanlar karşılık gelen çevre değişkenleri (env vars) ile
    override edilebilir. Öncelik sırası:
        1. Sistem environment variables
        2. .env dosyası
        3. Alan tanımındaki varsayılan değer

    Örnek .env dosyası::

        ISU_LOG_LEVEL=DEBUG
        ISU_ENGINE_PATH=/usr/local/bin/isu-secops-engine
        ISU_REPORTS_DIR=/var/log/isu-secops/reports
        ISU_SCAN_TIMEOUT=300
    """

    model_config = SettingsConfigDict(
        env_prefix="ISU_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Uygulama Genel Ayarları
    # ------------------------------------------------------------------

    app_name: str = Field(
        default="ISU-SecOps-Orchestrator",
        description="Uygulama adı (log ve rapor başlıklarında kullanılır).",
    )

    app_version: str = Field(
        default="1.0.0",
        description="Uygulama semantik versiyon numarası.",
    )

    app_host: str = Field(
        default="0.0.0.0",
        description="FastAPI sunucusunun dinleyeceği IP adresi.",
    )

    app_port: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        description="FastAPI sunucusunun dinleyeceği port numarası (1024-65535).",
    )

    debug: bool = Field(
        default=False,
        description="Debug modu. Production'da False olmalı.",
    )

    # ------------------------------------------------------------------
    # Loglama Ayarları
    # ------------------------------------------------------------------

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Python logging seviyesi.",
    )

    log_format: Literal["json", "text"] = Field(
        default="json",
        description="Log çıktı formatı. 'json' yapısal loglama için önerilir.",
    )

    # ------------------------------------------------------------------
    # Rust Engine Ayarları
    # ------------------------------------------------------------------

    engine_path: Path = Field(
        default=DEFAULT_ENGINE_PATH,
        description="ISU-SecOps-Engine Rust binary'sinin tam dosya yolu.",
    )

    scan_timeout: int = Field(
        default=120,
        ge=10,
        le=600,
        description=(
            "Tek bir tarama için maksimum bekleme süresi (saniye). "
            "Bu süre aşılırsa tarama iptal edilir ve EngineTimeoutError fırlatılır."
        ),
    )

    max_concurrent_scans: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Eş zamanlı çalışabilecek maksimum tarama sayısı.",
    )

    engine_args_extra: list[str] = Field(
        default_factory=list,
        description=(
            "Rust engine'e her çağrıda eklenecek ek argümanlar. "
            "Örn: ['--verbose', '--format=json']"
        ),
    )

    # ------------------------------------------------------------------
    # Raporlama Ayarları
    # ------------------------------------------------------------------

    reports_dir: Path = Field(
        default=DEFAULT_REPORTS_DIR,
        description="Üretilen Markdown raporlarının kaydedileceği dizin.",
    )

    report_include_remediation: bool = Field(
        default=True,
        description="Raporlara sıkılaştırma (remediation) önerileri dahil edilsin mi?",
    )

    report_include_cvss: bool = Field(
        default=True,
        description="CVSS risk skoru hesaplaması raporlara dahil edilsin mi?",
    )

    report_organization: str = Field(
        default="ISU Cyber Security Research Lab",
        description="Rapor başlıklarında görünecek kurum/organizasyon adı.",
    )

    # ------------------------------------------------------------------
    # Güvenlik Ayarları
    # ------------------------------------------------------------------

    allowed_scan_targets: list[str] = Field(
        default_factory=list,
        description=(
            "İzin verilen tarama hedefleri. Boş liste ise tüm hedeflere izin verilir. "
            "Örn: ['192.168.1.0/24', '10.0.0.0/8', 'internal.corp.com']"
        ),
    )

    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:8080"],
        description="CORS için izin verilen origin listesi.",
    )

    # ------------------------------------------------------------------
    # Validatorlar
    # ------------------------------------------------------------------

    @field_validator("engine_path", mode="before")
    @classmethod
    def resolve_engine_path(cls, v: str | Path) -> Path:
        """Engine yolunu mutlak yola dönüştür."""
        return Path(v).resolve()

    @field_validator("reports_dir", mode="before")
    @classmethod
    def resolve_reports_dir(cls, v: str | Path) -> Path:
        """Rapor dizinini mutlak yola dönüştür."""
        return Path(v).resolve()

    @model_validator(mode="after")
    def ensure_reports_dir_exists(self) -> "AppSettings":
        """Rapor dizini yoksa oluştur."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        return self

    # ------------------------------------------------------------------
    # Yardımcı Metodlar
    # ------------------------------------------------------------------

    @property
    def engine_exists(self) -> bool:
        """Rust binary'sinin disk üzerinde mevcut olup olmadığını kontrol eder."""
        return self.engine_path.exists() and self.engine_path.is_file()

    @property
    def engine_executable(self) -> bool:
        """Rust binary'sinin çalıştırılabilir (executable) olup olmadığını kontrol eder."""
        return self.engine_exists and os.access(self.engine_path, os.X_OK)

    def as_safe_dict(self) -> dict:
        """
        Hassas bilgiler maskelenmiş konfigürasyon sözlüğü döner.
        Log çıktıları ve /health endpoint için kullanılır.
        """
        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "log_level": self.log_level,
            "debug": self.debug,
            "engine_path": str(self.engine_path),
            "engine_exists": self.engine_exists,
            "scan_timeout": self.scan_timeout,
            "max_concurrent_scans": self.max_concurrent_scans,
            "reports_dir": str(self.reports_dir),
            "report_organization": self.report_organization,
        }


# ---------------------------------------------------------------------------
# Singleton Fabrika Fonksiyonu
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """
    Uygulama boyunca tek bir AppSettings örneği döndüren fabrika fonksiyonu.

    ``@lru_cache`` sayesinde konfigürasyon yalnızca bir kez okunur ve
    ardından önbellekten servis edilir. Test sırasında önbelleği temizlemek
    için ``get_settings.cache_clear()`` kullanın.

    Returns:
        AppSettings: Geçerli konfigürasyon nesnesi.

    Example::

        from orchestrator.app.config import get_settings

        settings = get_settings()
        print(settings.engine_path)
    """
    return AppSettings()
