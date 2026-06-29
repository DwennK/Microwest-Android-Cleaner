from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class ConnectionTab:
    def __init__(self, window: object) -> None:
        self.window = window

    def build(self) -> QWidget:
        window = self.window
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        window.model_label = QLabel("-")
        window.android_label = QLabel("-")
        window.serial_label = QLabel("-")
        window.device_combo = QComboBox()
        window.device_combo.addItem("Auto", "")

        window.quick_scan_button = QPushButton("Diagnostic rapide")
        window.quick_scan_button.setObjectName("PrimaryButton")
        window.detect_button = QPushButton("Détecter téléphone")
        window.detect_button.setObjectName("PrimaryButton")
        window.adb_diagnostic_button = QPushButton("Diagnostic ADB")
        window.adb_repair_button = QPushButton("Réparer connexion")
        window.adb_daemon_button = QPushButton("Redémarrer ADB")
        window.adb_daemon_button.setContextMenuPolicy(Qt.CustomContextMenu)
        window.copy_diagnostic_button = QPushButton("Copier diagnostic")
        window.export_diagnostic_button = QPushButton("Exporter diagnostic")
        window.copy_diagnostic_button.setEnabled(False)
        window.export_diagnostic_button.setEnabled(False)

        phone_box = QGroupBox("Téléphone")
        phone_layout = QGridLayout(phone_box)
        phone_layout.setHorizontalSpacing(14)
        phone_layout.setVerticalSpacing(8)
        phone_layout.addWidget(QLabel("Modèle"), 0, 0)
        phone_layout.addWidget(window.model_label, 0, 1)
        phone_layout.addWidget(QLabel("Android"), 0, 2)
        phone_layout.addWidget(window.android_label, 0, 3)
        phone_layout.addWidget(QLabel("ADB"), 1, 0)
        phone_layout.addWidget(window.serial_label, 1, 1)
        phone_layout.addWidget(QLabel("Appareil"), 1, 2)
        phone_layout.addWidget(window.device_combo, 1, 3)
        phone_layout.setColumnStretch(1, 1)
        phone_layout.setColumnStretch(3, 2)
        layout.addWidget(phone_box)

        actions = QHBoxLayout()
        for button in (
            window.quick_scan_button,
            window.detect_button,
            window.adb_repair_button,
            window.adb_diagnostic_button,
            window.adb_daemon_button,
        ):
            actions.addWidget(button)
        actions.addStretch(1)
        layout.addLayout(actions)

        diagnostic_actions = QHBoxLayout()
        for button in (window.copy_diagnostic_button, window.export_diagnostic_button):
            diagnostic_actions.addWidget(button)
        diagnostic_actions.addStretch(1)
        layout.addLayout(diagnostic_actions)

        workflow_box = QGroupBox("Parcours recommandé")
        workflow_layout = QGridLayout(workflow_box)
        workflow_layout.setHorizontalSpacing(16)
        workflow_layout.setVerticalSpacing(8)
        steps = (
            ("1", "Brancher", "USB + débogage activé"),
            ("2", "Scanner", "Apps utilisateur par défaut"),
            ("3", "Valider", "Vérification humaine obligatoire"),
            ("4", "Exporter", "Rapport ou plan d'action"),
        )
        for column, (number, title, body) in enumerate(steps):
            step_title = QLabel(f"{number}. {title}")
            step_title.setObjectName("StepCardTitle")
            step_body = QLabel(body)
            step_body.setObjectName("Muted")
            step_body.setWordWrap(True)
            workflow_layout.addWidget(step_title, 0, column)
            workflow_layout.addWidget(step_body, 1, column)
            workflow_layout.setColumnStretch(column, 1)
        layout.addWidget(workflow_box)

        hint = QLabel(
            "Si le téléphone reste bloqué sur unauthorized, regardez son écran et acceptez la clé RSA. "
            "Si l'état passe offline, utilisez Réparer connexion puis relancez Diagnostic rapide."
        )
        hint.setWordWrap(True)
        hint.setObjectName("Muted")
        layout.addWidget(hint)
        layout.addStretch(1)
        return tab
