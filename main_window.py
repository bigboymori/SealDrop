"""Main desktop window for SealDrop GUI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

from PySide6 import QtCore, QtGui, QtWidgets

from ..errors import AuthenticationError, ConfigError, PackageFormatError, SafetyError
from ..package import create_package, extract_package, inspect_package, verify_package
from ..signature import SignatureVerifyResult, inspect_signatures, parse_public_key_mappings, sign_package, verify_signatures
from .async_worker import BackgroundTask
from .dialogs import (
    ask_passphrase,
    ask_signer_id,
    choose_input_file,
    choose_output_directory,
    choose_output_package,
    choose_package_file,
    choose_private_key,
)
from .dragdrop import DragDropController
from .metadata_panel import MetadataPanel
from .package_view import PackageView
from .signature_dialog import SignatureResultsDialog
from .toolbar import SealDropToolbar
from .trust_log import TrustLog


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SealDrop")
        self.resize(1060, 700)

        self.loaded_package: Path | None = None
        self._thread_pool = QtCore.QThreadPool(self)
        self._active_task: BackgroundTask | None = None

        self.toolbar = SealDropToolbar(self)
        self.addToolBar(QtCore.Qt.TopToolBarArea, self.toolbar)

        self.package_view = PackageView(self)
        self.metadata_panel = MetadataPanel(self)
        self.trust_log = TrustLog(self)

        top_splitter = QtWidgets.QSplitter(self)
        top_splitter.addWidget(self.package_view)
        top_splitter.addWidget(self.metadata_panel)
        top_splitter.setSizes([680, 360])

        vertical_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical, self)
        vertical_splitter.addWidget(top_splitter)
        vertical_splitter.addWidget(self.trust_log)
        vertical_splitter.setSizes([500, 180])
        self.setCentralWidget(vertical_splitter)

        self.statusBar().showMessage("Ready")

        self._wire_actions()
        self._setup_menu()
        self._setup_shortcuts()

        self._dragdrop = DragDropController(self, self)
        self.setAcceptDrops(True)
        self._set_action_state()

    def _wire_actions(self) -> None:
        self.toolbar.actions_bundle.seal.triggered.connect(self.on_seal_clicked)
        self.toolbar.actions_bundle.open_pkg.triggered.connect(self.on_open_clicked)
        self.toolbar.actions_bundle.verify.triggered.connect(self.on_verify_clicked)
        self.toolbar.actions_bundle.verify_signatures.triggered.connect(self.on_verify_signatures_clicked)
        self.toolbar.actions_bundle.extract.triggered.connect(self.on_extract_clicked)
        self.toolbar.actions_bundle.sign.triggered.connect(self.on_sign_clicked)

    def _setup_menu(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        file_menu.addAction(self.toolbar.actions_bundle.seal)
        file_menu.addAction(self.toolbar.actions_bundle.open_pkg)
        file_menu.addSeparator()

        clear_action = QtGui.QAction("Clear Session", self)
        clear_action.triggered.connect(self._clear_loaded_package)
        file_menu.addAction(clear_action)

        file_menu.addSeparator()
        exit_action = QtGui.QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        ops_menu = menu.addMenu("&Operations")
        ops_menu.addAction(self.toolbar.actions_bundle.verify)
        ops_menu.addAction(self.toolbar.actions_bundle.verify_signatures)
        ops_menu.addAction(self.toolbar.actions_bundle.extract)
        ops_menu.addAction(self.toolbar.actions_bundle.sign)

        view_menu = menu.addMenu("&View")
        clear_log = QtGui.QAction("Clear Trust Log", self)
        clear_log.triggered.connect(self.trust_log.clear)
        view_menu.addAction(clear_log)

    def _setup_shortcuts(self) -> None:
        self.toolbar.actions_bundle.seal.setShortcut("Ctrl+S")
        self.toolbar.actions_bundle.open_pkg.setShortcut("Ctrl+O")
        self.toolbar.actions_bundle.verify.setShortcut("Ctrl+Shift+V")
        self.toolbar.actions_bundle.verify_signatures.setShortcut("Ctrl+Shift+G")
        self.toolbar.actions_bundle.extract.setShortcut("Ctrl+E")
        self.toolbar.actions_bundle.sign.setShortcut("Ctrl+G")

    def _action_list(self) -> list[QtGui.QAction]:
        return [
            self.toolbar.actions_bundle.seal,
            self.toolbar.actions_bundle.open_pkg,
            self.toolbar.actions_bundle.verify,
            self.toolbar.actions_bundle.verify_signatures,
            self.toolbar.actions_bundle.extract,
            self.toolbar.actions_bundle.sign,
        ]

    def _set_busy(self, busy: bool, message: str = "") -> None:
        if busy:
            for action in self._action_list():
                action.setEnabled(False)
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
            if message:
                self.statusBar().showMessage(message)
        else:
            QtWidgets.QApplication.restoreOverrideCursor()
            self._set_action_state()

    def _set_action_state(self) -> None:
        has_pkg = self.loaded_package is not None
        self.toolbar.actions_bundle.seal.setEnabled(True)
        self.toolbar.actions_bundle.open_pkg.setEnabled(True)
        self.toolbar.actions_bundle.verify.setEnabled(has_pkg)
        self.toolbar.actions_bundle.verify_signatures.setEnabled(has_pkg)
        self.toolbar.actions_bundle.extract.setEnabled(has_pkg)
        self.toolbar.actions_bundle.sign.setEnabled(has_pkg)

    def _append_log(self, text: str) -> None:
        self.trust_log.append_event(text)

    def _handle_exception(self, exc: Exception) -> None:
        self.statusBar().showMessage(f"✖ {exc}", 6000)
        self._append_log(f"FAIL: {exc}")
        QtWidgets.QMessageBox.critical(self, "SealDrop", str(exc))

    def _run_background(
        self,
        *,
        busy_message: str,
        fn: Callable[[], object],
        on_success: Callable[[object], None],
        on_error: Callable[[Exception], bool] | None = None,
    ) -> bool:
        if self._active_task is not None:
            self.statusBar().showMessage("Another operation is already running", 3000)
            return False

        task = BackgroundTask(fn)
        self._active_task = task
        self._set_busy(True, busy_message)

        def _finish() -> None:
            self._active_task = None
            self._set_busy(False)

        def _handle_result(result: object) -> None:
            _finish()
            try:
                on_success(result)
            except Exception as exc:  # noqa: BLE001
                self._handle_exception(exc)

        def _handle_error(exc: Exception, tb: str) -> None:
            _finish()
            self._append_log(tb.strip())
            if on_error is not None and on_error(exc):
                return
            self._handle_exception(exc)

        task.signals.result.connect(_handle_result)
        task.signals.error.connect(_handle_error)
        self._thread_pool.start(task)
        return True

    def _clear_loaded_package(self) -> None:
        self.loaded_package = None
        self.package_view.clear_entries()
        self.metadata_panel.clear()
        self._set_action_state()
        self.statusBar().showMessage("Session cleared", 3000)
        self._append_log("Session cleared")

    def dragEnterEvent(self, event: QtGui.QDragEnterEvent) -> None:  # noqa: N802
        self._dragdrop.drag_enter(event)

    def dropEvent(self, event: QtGui.QDropEvent) -> None:  # noqa: N802
        self._dragdrop.drop(event)

    def seal_dropped_file(self, path: Path) -> None:
        self._seal_file(path)

    def on_seal_clicked(self) -> None:
        path = choose_input_file(self)
        if not path:
            return
        self._seal_file(path)

    def _seal_file(self, input_path: Path) -> None:
        suggested_out = input_path.with_name(input_path.name + ".sdpkg")
        out_path = choose_output_package(self, suggested_out)
        if not out_path:
            return

        note, _ = QtWidgets.QInputDialog.getText(
            self,
            "Optional note",
            "Optional sender note (encrypted metadata):",
            text="",
        )
        deterministic = (
            QtWidgets.QMessageBox.question(
                self,
                "Deterministic mode",
                "Use deterministic mode for reproducible package bytes?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            == QtWidgets.QMessageBox.Yes
        )

        passphrase = ask_passphrase(self, confirm=True)
        if passphrase is None:
            return

        self._run_background(
            busy_message="Sealing file...",
            fn=lambda: create_package(
                input_path,
                out_path,
                passphrase,
                note=note,
                deterministic=deterministic,
            ),
            on_success=lambda result: self._after_seal(input_path, result, deterministic),
        )

    def _after_seal(self, input_path: Path, result: object, deterministic: bool) -> None:
        pkg = result
        self.statusBar().showMessage(f"🔒 Package sealed: {pkg.package_path}", 5000)
        self._append_log(
            f"Sealed {input_path.name} -> {pkg.package_path.name} (deterministic={'yes' if deterministic else 'no'})"
        )
        self.open_package(pkg.package_path, auto_verify=False)

    def on_open_clicked(self) -> None:
        path = choose_package_file(self)
        if not path:
            return
        self.open_package(path, auto_verify=True)

    def open_package(self, path: Path, *, auto_verify: bool) -> None:
        self._run_background(
            busy_message="Opening package...",
            fn=lambda: inspect_package(path),
            on_success=lambda inspected: self._after_open(path, inspected, auto_verify),
        )

    def _after_open(self, path: Path, inspected: object, auto_verify: bool) -> None:
        self.loaded_package = path
        self.package_view.show_placeholder_package(path.name, inspected.package_size)
        self.metadata_panel.set_header_info(
            package_name=path.name,
            package_size=inspected.package_size,
            cipher=inspected.cipher,
            kdf=inspected.kdf,
            created_utc=inspected.created_utc,
        )
        self.metadata_panel.set_status("unknown", "🔒 Encrypted package loaded")
        self.metadata_panel.set_trust_summary("Inspect complete. Verify before extraction.")
        self._refresh_signature_overview()
        self.statusBar().showMessage("🔒 Encrypted package loaded", 4000)
        self._append_log(f"Opened package: {path}")
        self._set_action_state()

        if auto_verify:
            self.on_verify_clicked()

    def _refresh_signature_overview(self) -> None:
        if not self.loaded_package:
            self.metadata_panel.set_signature_info("-")
            return
        try:
            summary = inspect_signatures(self.loaded_package)
            if not summary.records:
                self.metadata_panel.set_signature_info("No signatures")
                return
            signers = sorted({record.signer for record in summary.records})
            self.metadata_panel.set_signature_info(
                f"{len(summary.records)} signature(s): " + ", ".join(signers)
            )
        except (ConfigError, PackageFormatError):
            self.metadata_panel.set_signature_info("Signature sidecar unreadable")

    def _ask_signature_key_mappings(self) -> dict[str, Path]:
        text, ok = QtWidgets.QInputDialog.getMultiLineText(
            self,
            "Signer public keys",
            "Enter signer mappings (one per line):\nname=/path/to/public_key.pem",
            "",
        )
        if not ok or not text.strip():
            return {}
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return parse_public_key_mappings(lines)

    def on_verify_clicked(self) -> None:
        if not self.loaded_package:
            return

        passphrase = ask_passphrase(self, confirm=False)
        if passphrase is None:
            self.statusBar().showMessage("Verification canceled", 3000)
            return

        key_map: dict[str, Path] = {}
        sidecar_path = self.loaded_package.with_name(self.loaded_package.name + ".sig.json")
        if sidecar_path.exists():
            answer = QtWidgets.QMessageBox.question(
                self,
                "Signature sidecar detected",
                "A signature sidecar was found. Verify signatures now?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            if answer == QtWidgets.QMessageBox.Yes:
                try:
                    key_map = self._ask_signature_key_mappings()
                except ConfigError as exc:
                    self._handle_exception(exc)
                    return

        def _task() -> tuple[object, SignatureVerifyResult | None, bool, Path]:
            verified = verify_package(self.loaded_package, passphrase)
            sig_result = verify_signatures(self.loaded_package, key_map) if key_map else None
            return verified, sig_result, sidecar_path.exists(), sidecar_path

        self._run_background(
            busy_message="Verifying package...",
            fn=_task,
            on_success=lambda result: self._after_verify(result),
        )

    def _after_verify(self, payload: object) -> None:
        verified, sig_result, sidecar_exists, sidecar_path = payload

        self.package_view.show_verified_file(verified.file_name, verified.file_size)
        self.metadata_panel.set_verified_info(
            file_name=verified.file_name,
            file_size=verified.file_size,
            created_utc=verified.created_utc,
        )

        trust_lines = [
            "Package auth/integrity: PASS",
            f"File hash: {verified.file_sha256}",
        ]
        trust_state = "verified"

        if sig_result is not None:
            failed = [item for item in sig_result.checks if item.status == "fail"]
            passed = [item for item in sig_result.checks if item.status == "pass"]
            unknown = [item for item in sig_result.checks if item.status == "unknown"]
            trust_lines.append(f"Signatures: {len(passed)} pass / {len(failed)} fail / {len(unknown)} unknown")
            for item in sig_result.checks:
                trust_lines.append(f"  {item.signer}: {item.status.upper()} ({item.reason})")
            if failed:
                trust_state = "failed"
                self.metadata_panel.set_status("failed", "✖ Signature verification failed")
            else:
                self.metadata_panel.set_status("verified", "✔ Package verified")

            dialog = SignatureResultsDialog(
                package_path=self.loaded_package,
                sidecar_path=sidecar_path,
                checks=sig_result.checks,
                parent=self,
            )
            dialog.exec()
        else:
            if sidecar_exists:
                trust_lines.append("Signatures: UNKNOWN (sidecar present; no keys provided)")
            else:
                trust_lines.append("Signatures: UNKNOWN (no sidecar)")
            self.metadata_panel.set_status("verified", "✔ Package verified")

        self.metadata_panel.set_trust_summary(" | ".join(trust_lines[:2]))
        self._refresh_signature_overview()
        for line in trust_lines:
            self._append_log(line)

        if trust_state == "failed":
            self.statusBar().showMessage("✖ Signature invalid", 6000)
        else:
            self.statusBar().showMessage("✔ Package verified", 5000)

    def on_verify_signatures_clicked(self) -> None:
        if not self.loaded_package:
            return
        sidecar_path = self.loaded_package.with_name(self.loaded_package.name + ".sig.json")
        if not sidecar_path.exists():
            QtWidgets.QMessageBox.information(
                self,
                "No signatures",
                "No signature sidecar was found for this package.",
            )
            self.metadata_panel.set_signature_info("No signatures")
            self._append_log("Signature verify requested but no sidecar exists")
            return

        try:
            key_map = self._ask_signature_key_mappings()
        except ConfigError as exc:
            self._handle_exception(exc)
            return
        if not key_map:
            self.statusBar().showMessage("Signature verification canceled", 3000)
            return

        self._run_background(
            busy_message="Verifying signatures...",
            fn=lambda: verify_signatures(self.loaded_package, key_map),
            on_success=lambda sig_result: self._after_verify_signatures(sig_result, sidecar_path),
        )

    def _after_verify_signatures(self, sig_result: SignatureVerifyResult, sidecar_path: Path) -> None:
        failed = [item for item in sig_result.checks if item.status == "fail"]
        passed = [item for item in sig_result.checks if item.status == "pass"]
        unknown = [item for item in sig_result.checks if item.status == "unknown"]

        self.metadata_panel.set_signature_info(
            f"{len(passed)} pass / {len(failed)} fail / {len(unknown)} unknown"
        )
        self.metadata_panel.set_trust_summary("Manual signature verification completed")

        if failed:
            self.metadata_panel.set_status("failed", "✖ Signature verification failed")
            self.statusBar().showMessage("✖ Signature invalid", 6000)
        elif passed:
            self.metadata_panel.set_status("verified", "✔ Signatures verified")
            self.statusBar().showMessage("✔ Signatures verified", 5000)
        else:
            self.metadata_panel.set_status("unknown", "Signature trust unresolved")
            self.statusBar().showMessage("Signatures unresolved", 5000)

        self._append_log(
            f"Signature verify: {len(passed)} pass / {len(failed)} fail / {len(unknown)} unknown"
        )
        for item in sig_result.checks:
            self._append_log(f"  {item.signer}: {item.status.upper()} ({item.reason})")

        dialog = SignatureResultsDialog(
            package_path=self.loaded_package,
            sidecar_path=sidecar_path,
            checks=sig_result.checks,
            parent=self,
        )
        dialog.exec()

    def on_extract_clicked(self) -> None:
        if not self.loaded_package:
            return
        out_dir = choose_output_directory(self)
        if not out_dir:
            return
        passphrase = ask_passphrase(self, confirm=False)
        if passphrase is None:
            return

        self._start_extract(out_dir=out_dir, passphrase=passphrase, overwrite=False)

    def _start_extract(self, *, out_dir: Path, passphrase: str, overwrite: bool) -> None:
        self._run_background(
            busy_message="Extracting package..." if not overwrite else "Extracting with overwrite...",
            fn=lambda: extract_package(self.loaded_package, out_dir, passphrase, overwrite=overwrite),
            on_success=lambda destination: self._after_extract(destination, overwrite),
            on_error=lambda exc: self._handle_extract_error(exc, out_dir, passphrase, overwrite),
        )

    def _after_extract(self, destination: object, overwrite: bool) -> None:
        self.statusBar().showMessage(f"✔ Extracted: {destination}", 6000)
        if overwrite:
            self._append_log(f"Extracted package with overwrite -> {destination}")
        else:
            self._append_log(f"Extracted package -> {destination}")

    def _handle_extract_error(self, exc: Exception, out_dir: Path, passphrase: str, overwrite: bool) -> bool:
        if isinstance(exc, SafetyError) and "destination exists" in str(exc) and not overwrite:
            answer = QtWidgets.QMessageBox.question(
                self,
                "Destination exists",
                "Destination exists. Overwrite?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            if answer == QtWidgets.QMessageBox.Yes:
                self._start_extract(out_dir=out_dir, passphrase=passphrase, overwrite=True)
            return True
        return False

    def on_sign_clicked(self) -> None:
        if not self.loaded_package:
            return
        private_key = choose_private_key(self)
        if not private_key:
            return
        signer = ask_signer_id(self)
        if not signer:
            return

        self._run_background(
            busy_message="Signing package...",
            fn=lambda: sign_package(self.loaded_package, private_key, signer),
            on_success=lambda result: self._after_sign(result),
        )

    def _after_sign(self, result: object) -> None:
        self._refresh_signature_overview()
        self.metadata_panel.set_trust_summary(f"Latest signature by {result.signer}")
        self.statusBar().showMessage(f"✔ Package signed by {result.signer}", 6000)
        self._append_log(f"Signed package as {result.signer} ({result.signatures_total} total signatures)")


def launch_gui(initial_package: str | None = None) -> int:
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()

    if initial_package:
        path = Path(initial_package)
        if path.exists() and path.suffix.lower() == ".sdpkg":
            win.open_package(path, auto_verify=True)

    return app.exec()


def main() -> int:
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    return launch_gui(initial)


if __name__ == "__main__":
    raise SystemExit(main())
