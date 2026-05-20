"""Bottom trust/event log panel for SealDrop GUI."""

from __future__ import annotations

from datetime import datetime

from PySide6 import QtWidgets


class TrustLog(QtWidgets.QPlainTextEdit):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setPlaceholderText("Trust and operation events will appear here.")

    def append_event(self, message: str) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        self.appendPlainText(f"[{ts}Z] {message}")
