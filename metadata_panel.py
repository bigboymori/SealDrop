"""Right-side metadata panel for package details and trust status."""

from __future__ import annotations

from PySide6 import QtCore, QtWidgets


class MetadataPanel(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)

        self.status_label = QtWidgets.QLabel("UNKNOWN")
        self.status_label.setAlignment(QtCore.Qt.AlignCenter)
        self.status_label.setMinimumHeight(30)

        form = QtWidgets.QFormLayout()
        self.filename = QtWidgets.QLabel("-")
        self.file_size = QtWidgets.QLabel("-")
        self.package_size = QtWidgets.QLabel("-")
        self.cipher = QtWidgets.QLabel("-")
        self.kdf = QtWidgets.QLabel("-")
        self.created_utc = QtWidgets.QLabel("-")
        self.signatures = QtWidgets.QLabel("-")
        self.signatures.setWordWrap(True)
        self.trust_summary = QtWidgets.QLabel("-")
        self.trust_summary.setWordWrap(True)

        form.addRow("Filename", self.filename)
        form.addRow("File size", self.file_size)
        form.addRow("Package size", self.package_size)
        form.addRow("Cipher", self.cipher)
        form.addRow("KDF", self.kdf)
        form.addRow("Sealed at", self.created_utc)
        form.addRow("Signatures", self.signatures)
        form.addRow("Trust summary", self.trust_summary)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel("Verification status"))
        layout.addWidget(self.status_label)
        layout.addLayout(form)
        layout.addStretch(1)

        self.set_status("unknown", "No package loaded")

    def set_status(self, state: str, message: str) -> None:
        palette = {
            "verified": "#1f7a1f",
            "failed": "#9e1b1b",
            "unknown": "#555555",
        }
        color = palette.get(state, palette["unknown"])
        self.status_label.setText(message)
        self.status_label.setStyleSheet(
            f"background:{color};color:white;padding:6px;border-radius:4px;font-weight:600;"
        )

    def set_header_info(
        self,
        *,
        package_name: str,
        package_size: int,
        cipher: str,
        kdf: str,
        created_utc: str,
    ) -> None:
        self.filename.setText(package_name)
        self.file_size.setText("encrypted")
        self.package_size.setText(str(package_size))
        self.cipher.setText(cipher)
        self.kdf.setText(kdf)
        self.created_utc.setText(created_utc)

    def set_verified_info(self, *, file_name: str, file_size: int, created_utc: str) -> None:
        self.filename.setText(file_name)
        self.file_size.setText(str(file_size))
        self.created_utc.setText(created_utc)

    def set_signature_info(self, text: str) -> None:
        self.signatures.setText(text)

    def set_trust_summary(self, text: str) -> None:
        self.trust_summary.setText(text)

    def clear(self) -> None:
        self.filename.setText("-")
        self.file_size.setText("-")
        self.package_size.setText("-")
        self.cipher.setText("-")
        self.kdf.setText("-")
        self.created_utc.setText("-")
        self.signatures.setText("-")
        self.trust_summary.setText("-")
        self.set_status("unknown", "No package loaded")
