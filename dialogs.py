"""Dialog helpers for SealDrop GUI."""

from __future__ import annotations

import secrets
from pathlib import Path

from PySide6 import QtWidgets

from ..constants import MIN_PASSPHRASE_BYTES


def _passphrase_score(passphrase: str) -> tuple[int, str, str, str]:
    if not passphrase:
        return 0, "empty", "No passphrase entered", "Enter a passphrase to continue."

    text_len = len(passphrase)
    byte_len = len(passphrase.encode("utf-8"))
    has_lower = any(ch.islower() for ch in passphrase)
    has_upper = any(ch.isupper() for ch in passphrase)
    has_digit = any(ch.isdigit() for ch in passphrase)
    has_symbol = any(not ch.isalnum() and not ch.isspace() for ch in passphrase)
    words = [token for token in passphrase.strip().split() if token]

    score = 0
    if byte_len >= MIN_PASSPHRASE_BYTES:
        score += 1
    if text_len >= 16:
        score += 1
    if text_len >= 20:
        score += 1
    if text_len >= 24:
        score += 1
    if has_lower:
        score += 1
    if has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_symbol:
        score += 1
    if len(set(passphrase)) >= 10:
        score += 1
    if len(words) >= 4:
        score += 1

    percent = min(100, score * 10)
    if byte_len < MIN_PASSPHRASE_BYTES:
        return (
            percent,
            "weak",
            f"Too short ({byte_len} bytes)",
            f"Use at least {MIN_PASSPHRASE_BYTES} characters. Recommended: 16+ or 4+ random words.",
        )
    if score <= 4:
        return (
            percent,
            "weak",
            "Weak",
            "Increase length and randomness. Avoid names, phrases, or reused passwords.",
        )
    if score <= 7:
        return (
            percent,
            "ok",
            "Good",
            "Valid passphrase. For stronger protection, prefer 16+ random characters or 4+ random words.",
        )
    return (
        percent,
        "strong",
        "Strong",
        "Strong passphrase quality.",
    )


def _generate_recommended_passphrase() -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(5)]
    return "-".join(groups)


class PassphraseDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget, *, confirm: bool) -> None:
        super().__init__(parent)
        self._require_confirm = confirm
        self._passphrase_value = ""
        self.setWindowTitle("SealDrop passphrase")
        self.resize(560, 280)

        self._intro_label = QtWidgets.QLabel(
            f"Minimum: {MIN_PASSPHRASE_BYTES} characters. Recommended: 16+ random characters or 4+ random words."
        )
        self._intro_label.setWordWrap(True)

        self._passphrase_edit = QtWidgets.QLineEdit(self)
        self._passphrase_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self._passphrase_edit.setPlaceholderText("Enter passphrase")

        self._confirm_edit = QtWidgets.QLineEdit(self)
        self._confirm_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self._confirm_edit.setPlaceholderText("Confirm passphrase")
        self._confirm_edit.setVisible(confirm)

        self._show_checkbox = QtWidgets.QCheckBox("Show passphrase")
        self._show_checkbox.toggled.connect(self._toggle_show)

        self._generate_button = QtWidgets.QPushButton("Generate strong passphrase")
        self._generate_button.clicked.connect(self._fill_generated_passphrase)
        self._generate_button.setVisible(confirm)

        self._strength_label = QtWidgets.QLabel("No passphrase entered")
        self._strength_bar = QtWidgets.QProgressBar(self)
        self._strength_bar.setRange(0, 100)
        self._strength_bar.setValue(0)
        self._hint_label = QtWidgets.QLabel("Enter a passphrase to continue.")
        self._hint_label.setWordWrap(True)

        self._button_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel,
            parent=self,
        )
        self._button_box.accepted.connect(self._attempt_accept)
        self._button_box.rejected.connect(self.reject)
        self._ok_button = self._button_box.button(QtWidgets.QDialogButtonBox.Ok)
        if self._ok_button is not None:
            self._ok_button.setEnabled(False)

        form = QtWidgets.QFormLayout()
        form.addRow("Passphrase", self._passphrase_edit)
        if confirm:
            form.addRow("Confirm", self._confirm_edit)

        actions = QtWidgets.QHBoxLayout()
        actions.addWidget(self._show_checkbox)
        actions.addStretch(1)
        actions.addWidget(self._generate_button)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self._intro_label)
        layout.addLayout(form)
        layout.addLayout(actions)
        layout.addWidget(self._strength_label)
        layout.addWidget(self._strength_bar)
        layout.addWidget(self._hint_label)
        layout.addWidget(self._button_box)

        self._passphrase_edit.textChanged.connect(self._on_text_changed)
        self._confirm_edit.textChanged.connect(self._on_text_changed)
        self._passphrase_edit.setFocus()

    @property
    def passphrase(self) -> str:
        return self._passphrase_value

    def _toggle_show(self, show: bool) -> None:
        mode = QtWidgets.QLineEdit.Normal if show else QtWidgets.QLineEdit.Password
        self._passphrase_edit.setEchoMode(mode)
        self._confirm_edit.setEchoMode(mode)

    def _fill_generated_passphrase(self) -> None:
        generated = _generate_recommended_passphrase()
        self._passphrase_edit.setText(generated)
        if self._require_confirm:
            self._confirm_edit.setText(generated)

    def _set_strength_style(self, tone: str) -> None:
        color_map = {
            "weak": "#c0392b",
            "ok": "#d68910",
            "strong": "#1e8449",
            "empty": "#7f8c8d",
        }
        color = color_map.get(tone, "#7f8c8d")
        self._strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")

    def _validation_message(self) -> str | None:
        first = self._passphrase_edit.text()
        if not first:
            return "Passphrase is required."
        if len(first.encode("utf-8")) < MIN_PASSPHRASE_BYTES:
            return f"Passphrase must be at least {MIN_PASSPHRASE_BYTES} characters."
        if self._require_confirm:
            second = self._confirm_edit.text()
            if not second:
                return "Confirm the passphrase to continue."
            if first != second:
                return "Passphrases do not match."
        return None

    def _on_text_changed(self) -> None:
        percent, tone, label, hint = _passphrase_score(self._passphrase_edit.text())
        self._strength_bar.setValue(percent)
        self._set_strength_style(tone)
        self._strength_label.setText(f"Strength: {label}")

        validation_error = self._validation_message()
        if validation_error is not None:
            self._hint_label.setText(validation_error)
            if self._ok_button is not None:
                self._ok_button.setEnabled(False)
            return

        self._hint_label.setText(hint)
        if self._ok_button is not None:
            self._ok_button.setEnabled(True)

    def _attempt_accept(self) -> None:
        validation_error = self._validation_message()
        if validation_error is not None:
            QtWidgets.QMessageBox.warning(self, "Passphrase", validation_error)
            return
        self._passphrase_value = self._passphrase_edit.text()
        self.accept()


def ask_passphrase(parent: QtWidgets.QWidget, *, confirm: bool = False) -> str | None:
    dialog = PassphraseDialog(parent, confirm=confirm)
    if dialog.exec() != QtWidgets.QDialog.Accepted:
        return None
    return dialog.passphrase


def choose_input_file(parent: QtWidgets.QWidget) -> Path | None:
    file_path, _ = QtWidgets.QFileDialog.getOpenFileName(parent, "Select file to seal")
    return Path(file_path) if file_path else None


def choose_package_file(parent: QtWidgets.QWidget) -> Path | None:
    file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
        parent,
        "Open SealDrop package",
        filter="SealDrop Package (*.sdpkg);;All Files (*)",
    )
    return Path(file_path) if file_path else None


def choose_output_package(parent: QtWidgets.QWidget, suggested: Path) -> Path | None:
    file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
        parent,
        "Save package",
        str(suggested),
        "SealDrop Package (*.sdpkg)",
    )
    return Path(file_path) if file_path else None


def choose_output_directory(parent: QtWidgets.QWidget) -> Path | None:
    directory = QtWidgets.QFileDialog.getExistingDirectory(parent, "Select extract destination")
    return Path(directory) if directory else None


def ask_signer_id(parent: QtWidgets.QWidget) -> str | None:
    signer, ok = QtWidgets.QInputDialog.getText(parent, "Signer ID", "Signer label (example: alice):")
    if not ok:
        return None
    signer = signer.strip()
    if not signer:
        QtWidgets.QMessageBox.warning(parent, "Signer ID", "Signer label is required.")
        return None
    return signer


def choose_private_key(parent: QtWidgets.QWidget) -> Path | None:
    file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
        parent,
        "Select Ed25519 private key",
        filter="PEM Keys (*.pem);;All Files (*)",
    )
    return Path(file_path) if file_path else None
