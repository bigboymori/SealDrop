"""Center package list view for SealDrop GUI."""

from __future__ import annotations

from PySide6 import QtWidgets


class PackageView(QtWidgets.QTableWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(0, 3, parent)
        self.setHorizontalHeaderLabels(["Entry", "Size", "Status"])
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)

    def clear_entries(self) -> None:
        self.setRowCount(0)

    def show_placeholder_package(self, package_name: str, package_size: int) -> None:
        self.setRowCount(1)
        self.setItem(0, 0, QtWidgets.QTableWidgetItem(package_name))
        self.setItem(0, 1, QtWidgets.QTableWidgetItem(str(package_size)))
        self.setItem(0, 2, QtWidgets.QTableWidgetItem("Encrypted package loaded"))

    def show_verified_file(self, file_name: str, file_size: int) -> None:
        self.setRowCount(1)
        self.setItem(0, 0, QtWidgets.QTableWidgetItem(file_name))
        self.setItem(0, 1, QtWidgets.QTableWidgetItem(str(file_size)))
        self.setItem(0, 2, QtWidgets.QTableWidgetItem("Verified"))
