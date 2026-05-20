"""Drag-and-drop helpers for SealDrop GUI."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from PySide6 import QtGui, QtWidgets


class DropHandler(Protocol):
    def seal_dropped_file(self, path: Path) -> None: ...

    def open_package(self, path: Path, *, auto_verify: bool) -> None: ...


class DragDropController:
    def __init__(self, host: DropHandler, parent: QtWidgets.QWidget) -> None:
        self._host = host
        self._parent = parent

    def drag_enter(self, event: QtGui.QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        event.ignore()

    def drop(self, event: QtGui.QDropEvent) -> None:
        urls = event.mimeData().urls()
        if not urls:
            event.ignore()
            return

        path = Path(urls[0].toLocalFile())
        if not path.exists() or not path.is_file():
            QtWidgets.QMessageBox.warning(self._parent, "Drag and drop", "Dropped item is not a file.")
            return

        if path.suffix.lower() == ".sdpkg":
            self._host.open_package(path, auto_verify=True)
            return

        answer = QtWidgets.QMessageBox.question(
            self._parent,
            "Seal file",
            f"Seal this file into a .sdpkg package?\n\n{path}",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.Cancel,
            QtWidgets.QMessageBox.Yes,
        )
        if answer == QtWidgets.QMessageBox.Yes:
            self._host.seal_dropped_file(path)
