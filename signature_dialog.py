"""Signature verification details dialog."""

from __future__ import annotations

from pathlib import Path

from PySide6 import QtCore, QtWidgets

from ..signature import SignatureCheck


class SignatureResultsDialog(QtWidgets.QDialog):
    def __init__(
        self,
        *,
        package_path: Path,
        sidecar_path: Path,
        checks: tuple[SignatureCheck, ...],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Signature Verification Details")
        self.resize(760, 380)

        title = QtWidgets.QLabel(f"Package: {package_path.name}")
        title.setWordWrap(True)
        sidecar = QtWidgets.QLabel(f"Sidecar: {sidecar_path}")
        sidecar.setWordWrap(True)

        overall = self._overall_status(checks)
        summary = QtWidgets.QLabel(f"Overall signature trust: {overall}")
        summary.setStyleSheet("font-weight: 600;")

        table = QtWidgets.QTableWidget(0, 3, self)
        table.setHorizontalHeaderLabels(["Signer", "Status", "Reason"])
        table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)

        for row, check in enumerate(checks):
            table.insertRow(row)
            table.setItem(row, 0, QtWidgets.QTableWidgetItem(check.signer))
            table.setItem(row, 1, QtWidgets.QTableWidgetItem(check.status.upper()))
            table.setItem(row, 2, QtWidgets.QTableWidgetItem(check.reason))

        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.accept)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(sidecar)
        layout.addWidget(summary)
        layout.addWidget(table)
        layout.addWidget(close_btn, alignment=QtCore.Qt.AlignRight)

    @staticmethod
    def _overall_status(checks: tuple[SignatureCheck, ...]) -> str:
        if not checks:
            return "UNKNOWN"
        if any(check.status == "fail" for check in checks):
            return "FAIL"
        if any(check.status == "pass" for check in checks):
            if any(check.status == "unknown" for check in checks):
                return "PASS (with unknown signers)"
            return "PASS"
        return "UNKNOWN"
