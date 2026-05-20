"""Toolbar for core SealDrop file lifecycle actions."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6 import QtCore, QtGui, QtWidgets


@dataclass
class ToolbarActions:
    seal: QtGui.QAction
    open_pkg: QtGui.QAction
    verify: QtGui.QAction
    verify_signatures: QtGui.QAction
    extract: QtGui.QAction
    sign: QtGui.QAction


class SealDropToolbar(QtWidgets.QToolBar):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__("SealDrop", parent)
        self.setMovable(False)
        self.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)

        self.actions_bundle = ToolbarActions(
            seal=self._add_action("Seal", "Seal a file into .sdpkg"),
            open_pkg=self._add_action("Open", "Open a .sdpkg package"),
            verify=self._add_action("Verify", "Verify package integrity/authentication"),
            verify_signatures=self._add_action("Verify Sig", "Verify package signatures only"),
            extract=self._add_action("Extract", "Extract verified package"),
            sign=self._add_action("Sign", "Add Ed25519 signature sidecar"),
        )

    def _add_action(self, text: str, tip: str) -> QtGui.QAction:
        action = self.addAction(text)
        action.setToolTip(tip)
        return action
