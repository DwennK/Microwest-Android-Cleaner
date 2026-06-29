from __future__ import annotations

from PySide6.QtWidgets import QLabel, QTextEdit, QVBoxLayout, QWidget


class DetailsTab:
    def __init__(self, window: object) -> None:
        self.window = window

    def build(self) -> QWidget:
        window = self.window
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        window.details_title_label = QLabel("Détails sélection")
        window.details_title_label.setObjectName("SectionTitle")
        layout.addWidget(window.details_title_label)

        window.details_text = QTextEdit()
        window.details_text.setReadOnly(True)
        window.details_text.setPlaceholderText("Sélectionnez une application dans Résultats pour afficher ses détails.")
        layout.addWidget(window.details_text, 1)
        return tab
