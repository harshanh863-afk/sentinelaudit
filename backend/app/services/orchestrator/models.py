"""Scan progress tracking models."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class ProgressUpdate:
    progress: int
    stage: str
    timestamp: datetime


@dataclass
class ScannerError:
    scanner_name: str
    error: str
