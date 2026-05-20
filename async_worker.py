"""Background task runner for non-blocking GUI operations."""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6 import QtCore


class TaskSignals(QtCore.QObject):
    result = QtCore.Signal(object)
    error = QtCore.Signal(object, str)


class BackgroundTask(QtCore.QRunnable):
    def __init__(self, fn: Callable[[], Any]) -> None:
        super().__init__()
        self.fn = fn
        self.signals = TaskSignals()

    @QtCore.Slot()
    def run(self) -> None:
        try:
            result = self.fn()
            self.signals.result.emit(result)
        except Exception as exc:  # noqa: BLE001
            self.signals.error.emit(exc, traceback.format_exc())
