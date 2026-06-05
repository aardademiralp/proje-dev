"""
ISU-SecOps-Orchestrator — FastAPI Application
==============================================
SOAR orkestratörünün ana giriş noktası. BackgroundTasks mimarisi ile
büyük taramaların HTTP bağlantısını zaman aşımına uğratmadan yönetir.

Endpoints:
    POST /api/v1/scan          — Yeni tarama başlat
    GET  /api/v1/scan/{id}     — Tarama durumu/sonucu sorgula
    GET  /api/v1/reports       — Üretilmiş raporları listele
    GET  /api/v1/health        — Sistem sağlık kontrolü
    GET  /api/v1/             — API bilgisi

Author: ISU-SecOps Team
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

from .config import AppSettings, get_settings
from .reporter import VulnerabilityReportGenerator
from .scanner import (
    EngineCrashError,
    EngineError,
    EngineNotFoundError,
    EngineTimeoutError,
    RustEngineWrapper,
    ScanResult,
    ScanStatus,
)
from .utils import (
    generate_task_id,
    get_logger,
    sanitize_target,
    setup_logging,
    utc_now,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# In-Memory Görev Deposu
# ---------------------------------------------------------------------------
# Production'da Redis veya PostgreSQL ile değiştirilmelidir.

_task_store: dict[str, dict[str, Any]] = {}
"""Aktif ve tamamlanmış görevlerin in-memory deposu."""

_store_lock = asyncio.Lock()
"""Eşzamanlı görev deposu erişimi için asyncio kilidi."""

_concurrent_scan_semaphore: asyncio.Semaphore | None = None
"""Eşzamanlı tarama sınırlaması için semaphore."""


# ---------------------------------------------------------------------------
# Pydantic Request/Response Modelleri
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """POST /api/v1/scan endpoint giriş modeli."""

    target: str = Field(
        ...,
        description="Taranacak hedef. IPv4 adresi, CIDR aralığı veya hostname.",
        examples=["192.168.1.1", "10.0.0.0/24", "internal.corp.com"],
        min_length=1,
        max_length=253,
    )

    extra_args: list[str] = Field(
        default_factory=list,
        description="Engine'e geçirilecek ek komut satırı argümanları.",
        examples=[["--verbose", "--timeout=30"]],
    )

    priority: str = Field(
        default="normal",
        description="Tarama önceliği. ('low', 'normal', 'high')",
        pattern="^(low|normal|high)$",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Hedef formatını doğrula ve temizle."""
        return sanitize_target(v)

    @field_validator("extra_args")
    @classmethod
    def validate_extra_args(cls, v: list[str]) -> list[str]:
        """Ek argümanların güvenliğini kontrol et."""
        dangerous = {";", "&&", "||", "|", "`", "$", ">", "<", "&"}
        for arg in v:
            for char in dangerous:
                if char in arg:
                    raise ValueError(
                        f"Güvenlik ihlali: '{char}' karakteri ek argümanlarda kullanılamaz."
                    )
        return v


class ScanResponse(BaseModel):
    """POST /api/v1/scan endpoint yanıt modeli."""

    task_id: str = Field(description="Görev benzersiz kimliği.")
    status: str = Field(description="Görev durumu.")
    message: str = Field(description="Bilgi mesajı.")
    target: str = Field(description="Taranacak hedef.")
    submitted_at: str = Field(description="Görev gönderilme zamanı (ISO-8601).")
    status_url: str = Field(description="Durum sorgulamak için kullanılacak URL.")


class TaskStatusResponse(BaseModel):
    """GET /api/v1/scan/{task_id} endpoint yanıt modeli."""

    task_id: str
    status: str
    target: str
    submitted_at: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    hosts_found: int | None = None
    total_open_ports: int | None = None
    overall_risk: str | None = None
    report_path: str | None = None
    error_message: str | None = None


class HealthResponse(BaseModel):
    """GET /api/v1/health endpoint yanıt modeli."""

    status: str
    timestamp: str
    app_name: str
    app_version: str
    engine_available: bool
    engine_path: str
    engine_version: str
    active_tasks: int
    configuration: dict[str, Any]


class ReportListResponse(BaseModel):
    """GET /api/v1/reports endpoint yanıt modeli."""

    total: int
    reports: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Bağımlılık Enjeksiyonu (Dependency Injection)
# ---------------------------------------------------------------------------


def get_scanner(
    settings: Annotated[AppSettings, Depends(get_settings)],
) -> RustEngineWrapper:
    """RustEngineWrapper bağımlılığını oluşturur."""
    return RustEngineWrapper(settings=settings)


def get_reporter(
    settings: Annotated[AppSettings, Depends(get_settings)],
) -> VulnerabilityReportGenerator:
    """VulnerabilityReportGenerator bağımlılığını oluşturur."""
    return VulnerabilityReportGenerator(settings=settings)


# ---------------------------------------------------------------------------
# Arka Plan Görev Fonksiyonları
# ---------------------------------------------------------------------------


async def _execute_scan_task(
    task_id: str,
    target: str,
    extra_args: list[str],
    settings: AppSettings,
) -> None:
    """
    Arka planda çalışan tarama görev işleyicisi.

    Bu fonksiyon ``BackgroundTasks`` tarafından çağrılır ve HTTP yanıtı
    döndürüldükten sonra bağımsız olarak çalışmaya devam eder.

    Args:
        task_id: Görev benzersiz kimliği.
        target: Taranacak hedef.
        extra_args: Engine'e geçirilecek ek argümanlar.
        settings: Uygulama konfigürasyonu.
    """
    global _concurrent_scan_semaphore

    scanner = RustEngineWrapper(settings=settings)
    reporter = VulnerabilityReportGenerator(settings=settings)

    # Görev durumunu RUNNING'e güncelle
    async with _store_lock:
        if task_id in _task_store:
            _task_store[task_id]["status"] = ScanStatus.RUNNING.name
            _task_store[task_id]["started_at"] = utc_now().isoformat()

    logger.info(
        "Arka plan tarama görevi başlatıldı.",
        extra={"task_id": task_id, "target": target},
    )

    # Eşzamanlı tarama sınırlaması
    async with _concurrent_scan_semaphore:
        try:
            # Taramayı çalıştır
            scan_result: ScanResult = await scanner.run_scan(
                task_id=task_id,
                target=target,
                extra_args=extra_args,
            )

            # Rapor üret
            report_path: Path | None = None
            if scan_result.status == ScanStatus.COMPLETED:
                try:
                    report_path = reporter.generate(scan_result)
                    logger.info(
                        "Rapor başarıyla üretildi.",
                        extra={
                            "task_id": task_id,
                            "report_path": str(report_path),
                        },
                    )
                except Exception as exc:
                    logger.error(
                        "Rapor üretimi başarısız.",
                        extra={"task_id": task_id, "error": str(exc)},
                    )

            # Görev deposunu güncelle
            async with _store_lock:
                _task_store[task_id].update(
                    {
                        "status": scan_result.status.name,
                        "completed_at": scan_result.completed_at.isoformat()
                        if scan_result.completed_at
                        else None,
                        "duration_seconds": scan_result.duration_seconds,
                        "hosts_found": len(scan_result.hosts),
                        "total_open_ports": scan_result.total_open_ports,
                        "overall_risk": scan_result.overall_risk,
                        "report_path": str(report_path) if report_path else None,
                        "error_message": scan_result.error_message or None,
                    }
                )

        except EngineNotFoundError as exc:
            logger.error(
                "Engine bulunamadı.",
                extra={"task_id": task_id, "error": str(exc)},
            )
            async with _store_lock:
                _task_store[task_id].update(
                    {
                        "status": ScanStatus.FAILED.name,
                        "completed_at": utc_now().isoformat(),
                        "error_message": f"Engine bulunamadı: {exc.message}",
                    }
                )

        except EngineTimeoutError as exc:
            logger.warning(
                "Tarama zaman aşımına uğradı.",
                extra={
                    "task_id": task_id,
                    "timeout": exc.timeout,
                    "target": exc.target,
                },
            )
            async with _store_lock:
                _task_store[task_id].update(
                    {
                        "status": ScanStatus.TIMEOUT.name,
                        "completed_at": utc_now().isoformat(),
                        "error_message": f"Tarama {exc.timeout}s timeout'a uğradı.",
                    }
                )

        except (EngineCrashError, EngineError) as exc:
            logger.error(
                "Engine hatası.",
                extra={
                    "task_id": task_id,
                    "error": str(exc),
                    "return_code": getattr(exc, "return_code", None),
                },
            )
            async with _store_lock:
                _task_store[task_id].update(
                    {
                        "status": ScanStatus.FAILED.name,
                        "completed_at": utc_now().isoformat(),
                        "error_message": str(exc),
                    }
                )

        except Exception as exc:
            logger.exception(
                "Beklenmeyen hata.",
                extra={"task_id": task_id, "error": str(exc)},
            )
            async with _store_lock:
                _task_store[task_id].update(
                    {
                        "status": ScanStatus.FAILED.name,
                        "completed_at": utc_now().isoformat(),
                        "error_message": f"Beklenmeyen sistem hatası: {type(exc).__name__}",
                    }
                )


# ---------------------------------------------------------------------------
# Uygulama Yaşam Döngüsü (Lifespan)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI uygulama yaşam döngüsü yöneticisi.

    Başlangıçta:
        - Loglama altyapısını yapılandırır
        - Eşzamanlı tarama semaphore'unu başlatır
        - Engine erişilebilirliğini kontrol eder

    Kapanışta:
        - Aktif görevlerin tamamlanmasını bekler
        - Kaynakları temizler
    """
    global _concurrent_scan_semaphore

    settings = get_settings()
    setup_logging(
        level=settings.log_level,
        fmt=settings.log_format,
        app_name="isu-secops",
    )

    logger.info(
        "ISU-SecOps-Orchestrator başlatılıyor.",
        extra={
            "version": settings.app_version,
            "debug": settings.debug,
            "engine_path": str(settings.engine_path),
        },
    )

    _concurrent_scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)

    # Engine kontrolü (sadece uyarı, hata fırlatmaz)
    if not settings.engine_exists:
        logger.warning(
            "ISU-SecOps-Engine binary'si bulunamadı. "
            "Tarama işlevleri kullanılamayabilir.",
            extra={"engine_path": str(settings.engine_path)},
        )

    logger.info("ISU-SecOps-Orchestrator hazır.", extra=settings.as_safe_dict())

    yield

    logger.info("ISU-SecOps-Orchestrator kapatılıyor.")


# ---------------------------------------------------------------------------
# FastAPI Uygulaması
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """FastAPI uygulama fabrika fonksiyonu."""
    settings = get_settings()

    app = FastAPI(
        title="ISU-SecOps-Orchestrator",
        summary=(
            "SOAR tabanlı otomatik güvenlik keşfi ve raporlama orkestratörü. "
            "Rust tabanlı ISU-SecOps-Engine'i Python/FastAPI ile yönetir."
        ),
        description="""
## ISU-SecOps-Orchestrator API

Siber güvenlik SOAR (Security Orchestration, Automation, and Response)
platformunun REST API arayüzü.

### Özellikler
- ⚡ **Asenkron Tarama**: BackgroundTasks ile HTTP bağlantısını bloklamadan tarama
- 📊 **Profesyonel Raporlama**: OWASP Top 10 + CVE referanslı Markdown raporlar
- 🔒 **Güvenlik**: Hedef validasyonu, komut enjeksiyonu koruması
- 📈 **Ölçeklenebilir**: Eşzamanlı tarama sınırlaması ile kaynak yönetimi

### Hızlı Başlangıç
```bash
curl -X POST http://localhost:8000/api/v1/scan \\
  -H "Content-Type: application/json" \\
  -d '{"target": "192.168.1.1"}'
```
        """,
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    # Global Exception Handlers
    _register_exception_handlers(app)

    # Router'ları kaydet
    app.include_router(router, prefix="/api/v1")

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    """Global exception handler'ları kaydeder."""

    @app.exception_handler(EngineNotFoundError)
    async def engine_not_found_handler(
        request: Request, exc: EngineNotFoundError
    ) -> JSONResponse:
        logger.error(
            "Engine not found.",
            extra={"path": request.url.path, "error": exc.message},
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "ENGINE_NOT_FOUND",
                "message": exc.message,
                "hint": (
                    "ISU-SecOps-Engine binary'sini derleyin ve "
                    "ISU_ENGINE_PATH çevre değişkenini ayarlayın."
                ),
            },
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(
        request: Request, exc: ValueError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "VALIDATION_ERROR", "message": str(exc)},
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception(
            "İşlenmeyen istisna.",
            extra={"path": request.url.path, "error": str(exc)},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Beklenmeyen bir sistem hatası oluştu. Logları kontrol edin.",
            },
        )


# ---------------------------------------------------------------------------
# API Router
# ---------------------------------------------------------------------------

from fastapi import APIRouter  # noqa: E402

router = APIRouter(tags=["Security Operations"])


@router.get(
    "/",
    summary="API Bilgisi",
    response_description="API temel bilgileri",
)
async def api_root(
    settings: Annotated[AppSettings, Depends(get_settings)],
) -> dict[str, Any]:
    """ISU-SecOps-Orchestrator API bilgilerini döndürür."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": "SOAR tabanlı otomatik güvenlik keşfi ve raporlama API'si",
        "endpoints": {
            "scan": "POST /api/v1/scan",
            "scan_status": "GET /api/v1/scan/{task_id}",
            "reports": "GET /api/v1/reports",
            "health": "GET /api/v1/health",
            "docs": "GET /api/docs",
        },
        "timestamp": utc_now().isoformat(),
    }


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Yeni Tarama Başlat",
    response_description="Görev kimliği ve durum bilgisi",
)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    settings: Annotated[AppSettings, Depends(get_settings)],
) -> ScanResponse:
    """
    Belirtilen hedef için asenkron güvenlik taraması başlatır.

    Tarama, HTTP bağlantısını bloklamadan arka planda çalışır.
    Döndürülen `task_id` ile tarama durumu sorgulanabilir.

    **Desteklenen hedef formatları:**
    - IPv4: `192.168.1.1`
    - CIDR: `192.168.1.0/24`
    - Hostname: `internal.corp.com`
    """
    task_id = generate_task_id()
    submitted_at = utc_now()

    logger.info(
        "Yeni tarama isteği alındı.",
        extra={
            "task_id": task_id,
            "target": scan_request.target,
            "priority": scan_request.priority,
        },
    )

    # Görev deposuna ekle
    async with _store_lock:
        _task_store[task_id] = {
            "task_id": task_id,
            "status": ScanStatus.PENDING.name,
            "target": scan_request.target,
            "submitted_at": submitted_at.isoformat(),
            "started_at": None,
            "completed_at": None,
            "duration_seconds": None,
            "hosts_found": None,
            "total_open_ports": None,
            "overall_risk": None,
            "report_path": None,
            "error_message": None,
        }

    # Taramayı arka plana gönder
    background_tasks.add_task(
        _execute_scan_task,
        task_id=task_id,
        target=scan_request.target,
        extra_args=scan_request.extra_args,
        settings=settings,
    )

    return ScanResponse(
        task_id=task_id,
        status=ScanStatus.PENDING.name,
        message=(
            f"Tarama görevi başarıyla kuyruğa alındı. "
            f"Durum için GET /api/v1/scan/{task_id} adresini sorgulayın."
        ),
        target=scan_request.target,
        submitted_at=submitted_at.isoformat(),
        status_url=f"/api/v1/scan/{task_id}",
    )


@router.get(
    "/scan/{task_id}",
    response_model=TaskStatusResponse,
    summary="Tarama Durumu Sorgula",
    response_description="Görev durumu ve sonuç bilgileri",
)
async def get_scan_status(task_id: str) -> TaskStatusResponse:
    """
    Belirtilen görev kimliğinin durumunu ve sonuçlarını döndürür.

    **Durum değerleri:**
    - `PENDING`: Kuyruğa alındı, başlamadı
    - `RUNNING`: Devam ediyor
    - `COMPLETED`: Başarıyla tamamlandı
    - `FAILED`: Hata nedeniyle başarısız
    - `TIMEOUT`: Zaman aşımına uğradı
    """
    async with _store_lock:
        task = _task_store.get(task_id)

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "TASK_NOT_FOUND",
                "message": f"Görev bulunamadı: '{task_id}'",
                "hint": "Görev ID'sini kontrol edin veya yeni tarama başlatın.",
            },
        )

    return TaskStatusResponse(**task)


@router.get(
    "/scan/{task_id}/report",
    summary="Tarama Raporunu İndir",
    response_description="Markdown rapor dosyası",
)
async def download_report(task_id: str) -> FileResponse:
    """
    Tamamlanmış taramanın Markdown raporunu dosya olarak döndürür.

    Rapor, tarama tamamlandıktan sonra otomatik olarak üretilir.
    """
    async with _store_lock:
        task = _task_store.get(task_id)

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "TASK_NOT_FOUND", "message": f"Görev bulunamadı: '{task_id}'"},
        )

    if task["status"] != ScanStatus.COMPLETED.name:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "REPORT_NOT_READY",
                "message": f"Rapor henüz hazır değil. Görev durumu: {task['status']}",
            },
        )

    report_path = task.get("report_path")
    if not report_path or not Path(report_path).exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "REPORT_FILE_NOT_FOUND", "message": "Rapor dosyası bulunamadı."},
        )

    return FileResponse(
        path=report_path,
        media_type="text/markdown",
        filename=Path(report_path).name,
    )


@router.get(
    "/reports",
    response_model=ReportListResponse,
    summary="Rapor Listesi",
    response_description="Üretilmiş raporların listesi",
)
async def list_reports(
    settings: Annotated[AppSettings, Depends(get_settings)],
    limit: int = 50,
    offset: int = 0,
) -> ReportListResponse:
    """
    Üretilmiş tüm Markdown raporlarını listeler.

    Raporlar en yeni tarihten başlayarak sıralanır.
    """
    reports_dir = settings.reports_dir
    if not reports_dir.exists():
        return ReportListResponse(total=0, reports=[])

    report_files = sorted(
        reports_dir.glob("*.md"),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )

    total = len(report_files)
    paginated = report_files[offset : offset + limit]

    reports = []
    for report_file in paginated:
        stat = report_file.stat()
        reports.append(
            {
                "filename": report_file.name,
                "path": str(report_file),
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime, UTC).isoformat(),
                "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                "download_url": f"/api/v1/reports/{report_file.name}",
            }
        )

    return ReportListResponse(total=total, reports=reports)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Sistem Sağlık Kontrolü",
    response_description="Sistem ve engine sağlık durumu",
)
async def health_check(
    settings: Annotated[AppSettings, Depends(get_settings)],
) -> HealthResponse:
    """
    ISU-SecOps-Orchestrator ve bağımlı servislerin sağlık durumunu döndürür.

    Kubernetes liveness/readiness probe için kullanılabilir.
    """
    scanner = RustEngineWrapper(settings=settings)
    engine_health = await scanner.health_check()

    async with _store_lock:
        active_tasks = sum(
            1
            for t in _task_store.values()
            if t["status"] in (ScanStatus.PENDING.name, ScanStatus.RUNNING.name)
        )

    return HealthResponse(
        status="healthy" if engine_health["engine_available"] else "degraded",
        timestamp=utc_now().isoformat(),
        app_name=settings.app_name,
        app_version=settings.app_version,
        engine_available=engine_health["engine_available"],
        engine_path=engine_health["engine_path"],
        engine_version=engine_health["engine_version"],
        active_tasks=active_tasks,
        configuration=settings.as_safe_dict(),
    )


# ---------------------------------------------------------------------------
# Uygulama Başlangıcı
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "orchestrator.app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
