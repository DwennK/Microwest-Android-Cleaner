from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QGridLayout, QGroupBox, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget


class SettingsTab:
    def __init__(self, window: object) -> None:
        self.window = window

    def build(self) -> QWidget:
        window = self.window
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        self._build_demo_box(window, layout)
        self._build_ai_box(window, layout)
        self._build_storage_box(window, layout)
        layout.addStretch(1)
        return tab

    def _build_demo_box(self, window: object, layout: QVBoxLayout) -> None:
        window.demo_button = QPushButton("Mode démo")

        demo_box = QGroupBox("Démo")
        demo_layout = QGridLayout(demo_box)
        demo_layout.addWidget(window.demo_button, 0, 0)
        demo_help = QLabel("Charge un faux téléphone pour tester les filtres, rapports et actions sans Android branché.")
        demo_help.setWordWrap(True)
        demo_help.setObjectName("Muted")
        demo_layout.addWidget(demo_help, 0, 1)
        layout.addWidget(demo_box)

    def _build_ai_box(self, window: object, layout: QVBoxLayout) -> None:
        window.save_settings_button = QPushButton("Enregistrer paramètres")
        window.save_settings_button.setObjectName("PrimaryButton")

        ai_box = QGroupBox("Analyse IA")
        ai_layout = QGridLayout(ai_box)
        ai_layout.setHorizontalSpacing(12)
        ai_layout.setVerticalSpacing(8)

        window.ai_provider_combo = QComboBox()
        window.ai_provider_combo.addItem("OpenAI", "openai")
        window.ai_provider_combo.addItem("MiniMax", "minimax")
        provider_index = window.ai_provider_combo.findData(window.ai_analyzer.provider)
        window.ai_provider_combo.setCurrentIndex(max(0, provider_index))

        window.openai_model_input = QLineEdit(str(window.ui_settings.get("openai_model") or "gpt-4.1-mini"))
        window.openai_base_url_input = QLineEdit(str(window.ui_settings.get("openai_base_url") or ""))
        window.minimax_model_input = QLineEdit(str(window.ui_settings.get("minimax_model") or "MiniMax-M3"))
        window.minimax_base_url_input = QLineEdit(
            str(window.ui_settings.get("minimax_base_url") or "https://api.minimax.io/v1")
        )
        window.ai_api_key_input = QLineEdit()
        window.ai_api_key_input.setEchoMode(QLineEdit.Password)
        window.ai_key_status_label = QLabel("")
        window.ai_key_status_label.setObjectName("Muted")

        openai_model_label = QLabel("Modèle OpenAI")
        openai_base_url_label = QLabel("Base URL OpenAI")
        minimax_model_label = QLabel("Modèle MiniMax")
        minimax_base_url_label = QLabel("Base URL MiniMax")
        window.openai_settings_widgets = [
            openai_model_label,
            window.openai_model_input,
            openai_base_url_label,
            window.openai_base_url_input,
        ]
        window.minimax_settings_widgets = [
            minimax_model_label,
            window.minimax_model_input,
            minimax_base_url_label,
            window.minimax_base_url_input,
        ]

        ai_layout.setColumnMinimumWidth(0, 160)
        ai_layout.setColumnStretch(1, 1)
        ai_layout.addWidget(QLabel("Provider"), 0, 0)
        ai_layout.addWidget(window.ai_provider_combo, 0, 1)
        ai_layout.addWidget(window.ai_key_status_label, 0, 2)
        ai_layout.addWidget(QLabel("Clé API"), 1, 0)
        ai_layout.addWidget(window.ai_api_key_input, 1, 1, 1, 2)
        ai_layout.addWidget(openai_model_label, 2, 0)
        ai_layout.addWidget(window.openai_model_input, 2, 1, 1, 2)
        ai_layout.addWidget(openai_base_url_label, 3, 0)
        ai_layout.addWidget(window.openai_base_url_input, 3, 1, 1, 2)
        ai_layout.addWidget(minimax_model_label, 4, 0)
        ai_layout.addWidget(window.minimax_model_input, 4, 1, 1, 2)
        ai_layout.addWidget(minimax_base_url_label, 5, 0)
        ai_layout.addWidget(window.minimax_base_url_input, 5, 1, 1, 2)
        ai_layout.addWidget(window.save_settings_button, 6, 1)
        ai_hint = QLabel("Collez une clé pour l'ajouter à .env. Laissez le champ vide pour conserver la clé existante.")
        ai_hint.setWordWrap(True)
        ai_hint.setObjectName("Muted")
        ai_layout.addWidget(ai_hint, 7, 0, 1, 3)
        layout.addWidget(ai_box)

    def _build_storage_box(self, window: object, layout: QVBoxLayout) -> None:
        window.open_data_button = QPushButton("Ouvrir dossier data")
        window.open_logs_button = QPushButton("Ouvrir logs")
        window.reload_button = QPushButton("Recharger blacklist/whitelist")

        storage_box = QGroupBox("Stockage portable")
        storage_layout = QGridLayout(storage_box)
        storage_layout.addWidget(window.open_data_button, 0, 0)
        storage_layout.addWidget(window.open_logs_button, 0, 1)
        storage_layout.addWidget(window.reload_button, 1, 0, 1, 2)
        storage_note = QLabel("Paramètres, base locale, logs, cache et rapports restent dans le dossier de l'application.")
        storage_note.setWordWrap(True)
        storage_note.setObjectName("Muted")
        storage_layout.addWidget(storage_note, 2, 0, 1, 2)
        layout.addWidget(storage_box)
