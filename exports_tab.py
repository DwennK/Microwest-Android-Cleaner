from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QGroupBox, QPushButton, QVBoxLayout, QWidget


class ExportsTab:
    def __init__(self, window: object) -> None:
        self.window = window

    def build(self) -> QWidget:
        window = self.window
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        window.report_button = QPushButton("Exporter rapport")
        window.csv_button = QPushButton("Exporter CSV")
        window.action_plan_button = QPushButton("Plan action")
        window.copy_plan_button = QPushButton("Copier plan")
        window.open_reports_button = QPushButton("Ouvrir rapports")
        window.history_button = QPushButton("Historique")

        report_box = QGroupBox("Rapports et exports")
        report_layout = QGridLayout(report_box)
        report_layout.addWidget(window.report_button, 0, 0)
        report_layout.addWidget(window.csv_button, 0, 1)
        report_layout.addWidget(window.action_plan_button, 1, 0)
        report_layout.addWidget(window.copy_plan_button, 1, 1)
        report_layout.addWidget(window.open_reports_button, 2, 0)
        report_layout.addWidget(window.history_button, 2, 1)
        layout.addWidget(report_box)
        layout.addStretch(1)
        return tab
