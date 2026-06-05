"""
ISU-SecOps-Orchestrator — pytest Root Konfigürasyonu
=====================================================
Tüm test modülleri için paylaşılan konfigürasyon ve fixture'lar.

Bu dosya pytest tarafından otomatik keşfedilir ve proje kökünde
bulunarak tüm test paketleri için geçerlidir.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Projenin kök dizinini Python modül yoluna ekle.
# Bu sayede `from orchestrator.app.xxx import ...` importları çalışır.
_project_root = Path(__file__).resolve().parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))
