from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QGridLayout, QGroupBox, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget


class ScanTab:
    def __init__(self, window: object) -> None:
        self.window = window

    def build(self) -> QWidget:
        window = self.window
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(14)

        window.scan_quick_button = QPushButton("Diagnostic rapide")
        window.scan_quick_button.setObjectName("PrimaryButton")
        window.scan_button = QPushButton("Scanner les apps")
        window.scan_button.setObjectName("PrimaryButton")
        window.cancel_scan_button = QPushButton("Annuler scan")
        window.cancel_scan_button.setEnabled(False)
        window.ai_button = QPushButton("Analyser avec IA")
        window.include_system_checkbox = QCheckBox("Afficher apps système")

        window.scan_progress = QProgressBar()
        window.scan_progress.setRange(0, 100)
        window.scan_progress.setValue(0)
        window.scan_progress.setTextVisible(True)
        window.progress_label = QLabel("Prêt")

        controls = QGroupBox("Scan")
        controls_layout = QGridLayout(controls)
        controls_layout.setHorizontalSpacing(12)
        controls_layout.setVerticalSpacing(10)
        controls_layout.addWidget(window.scan_quick_button, 0, 0)
        controls_layout.addWidget(window.scan_button, 0, 1)
        controls_layout.addWidget(window.cancel_scan_button, 0, 2)
        controls_layout.addWidget(window.ai_button, 0, 3)
        controls_layout.addWidget(window.include_system_checkbox, 1, 0, 1, 4)
        controls_layout.addWidget(window.scan_progress, 2, 0, 1, 4)
        controls_layout.addWidget(window.progress_label, 3, 0, 1, 4)
        layout.addWidget(controls)

        hint = QLabel(
            "Diagnostic rapide détecte le téléphone si nécessaire, lance le scan utilisateur, puis ouvre Résultats."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addStretch(1)
        return tab
