from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)


class ResultsTab:
    def __init__(self, window: object) -> None:
        self.window = window

    def build(self) -> QWidget:
        window = self.window
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self._build_action_banner(window, layout)
        self._build_summary(window, layout)
        self._build_filters(window, layout)
        self._build_selection_toolbar(window, layout)
        self._build_table(window, layout)
        return tab

    def _build_action_banner(self, window: object, layout: QVBoxLayout) -> None:
        window.results_action_title_label = QLabel("Lancez un scan pour obtenir une synthèse.")
        window.results_action_title_label.setObjectName("ActionBannerTitle")
        window.results_action_body_label = QLabel(
            "Les applications système connues restent protégées. Toute désinstallation demande une validation humaine."
        )
        window.results_action_body_label.setObjectName("ActionBannerBody")
        window.results_action_body_label.setWordWrap(True)

        window.results_action_banner = QWidget()
        window.results_action_banner.setObjectName("ActionBanner")
        banner_layout = QVBoxLayout(window.results_action_banner)
        banner_layout.setContentsMargins(14, 12, 14, 12)
        banner_layout.setSpacing(4)
        banner_layout.addWidget(window.results_action_title_label)
        banner_layout.addWidget(window.results_action_body_label)
        layout.addWidget(window.results_action_banner)

    def _build_summary(self, window: object, layout: QVBoxLayout) -> None:
        window.summary_total_label = QLabel("Apps: 0")
        window.summary_high_label = QLabel("À traiter: 0")
        window.summary_review_label = QLabel("À vérifier: 0")
        window.summary_hidden_label = QLabel("Cachées: 0")
        window.summary_sideload_label = QLabel("Sideload: 0")
        window.summary_selected_label = QLabel("Cochées: 0")

        summary_strip = QHBoxLayout()
        for index, label in enumerate(
            (
                window.summary_total_label,
                window.summary_high_label,
                window.summary_review_label,
                window.summary_hidden_label,
                window.summary_sideload_label,
                window.summary_selected_label,
            )
        ):
            label.setObjectName("MetricLabel")
            summary_strip.addWidget(label)
            if index < 5:
                summary_strip.addSpacing(10)
        summary_strip.addStretch(1)
        layout.addLayout(summary_strip)

    def _build_filters(self, window: object, layout: QVBoxLayout) -> None:
        window.hide_safe_checkbox = QCheckBox("Masquer apps sûres")
        window.hidden_apps_checkbox = QCheckBox("Apps cachées")
        window.notification_audit_checkbox = QCheckBox("Audit notifications")
        window.sideload_checkbox = QCheckBox("Sideload")

        window.score_filter = QComboBox()
        window.score_filter.addItem("Score min: 0", 0)
        window.score_filter.addItem("Score min: 30", 30)
        window.score_filter.addItem("Score min: 60", 60)

        window.permission_filter = QComboBox()
        window.permission_filter.addItem("Toutes permissions", "")
        for permission in ("SMS", "CONTACTS", "CALL", "ACCESSIBILITY", "NOTIFICATION", "OVERLAY", "DEVICE_ADMIN", "VPN"):
            window.permission_filter.addItem(permission, permission)

        window.search_input = QLineEdit()
        window.search_input.setPlaceholderText("Rechercher nom, package, installateur...")

        filters_row = QHBoxLayout()
        filters_row.addWidget(window.search_input, 1)
        filters_row.addWidget(window.score_filter)
        filters_row.addWidget(window.permission_filter)
        layout.addLayout(filters_row)

        flags_row = QHBoxLayout()
        for checkbox in (
            window.hide_safe_checkbox,
            window.hidden_apps_checkbox,
            window.notification_audit_checkbox,
            window.sideload_checkbox,
        ):
            flags_row.addWidget(checkbox)
        flags_row.addStretch(1)
        layout.addLayout(flags_row)

    def _build_selection_toolbar(self, window: object, layout: QVBoxLayout) -> None:
        window.select_high_button = QPushButton("Cocher à traiter")
        window.select_review_button = QPushButton("Cocher à vérifier")
        window.clear_checks_button = QPushButton("Tout décocher")
        window.note_button = QPushButton("Ajouter note")
        window.open_settings_button = QPushButton("Ouvrir paramètres")
        window.uninstall_button = QPushButton("Désinstaller sélection")
        window.uninstall_button.setObjectName("DangerButton")

        selection_toolbar = QHBoxLayout()
        for button in (
            window.select_high_button,
            window.select_review_button,
            window.clear_checks_button,
            window.note_button,
            window.open_settings_button,
            window.uninstall_button,
        ):
            selection_toolbar.addWidget(button)
        selection_toolbar.addStretch(1)
        layout.addLayout(selection_toolbar)

    def _build_table(self, window: object, layout: QVBoxLayout) -> None:
        window.table = QTableWidget(0, len(window.COLUMNS))
        window.table.setHorizontalHeaderLabels(window.COLUMNS)
        window.table.setSortingEnabled(True)
        window.table.setSelectionBehavior(QTableWidget.SelectRows)
        window.table.setEditTriggers(QTableWidget.NoEditTriggers)
        window.table.setContextMenuPolicy(Qt.CustomContextMenu)
        window.table.setIconSize(QSize(28, 28))
        window.table.setAlternatingRowColors(True)
        window.table.verticalHeader().setVisible(False)
        window.table.verticalHeader().setDefaultSectionSize(32)

        header = window.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(window.COL_PACKAGE, QHeaderView.Stretch)
        window.table.setColumnWidth(0, 36)
        window.table.setColumnWidth(window.COL_PRIORITY, 96)
        window.table.setColumnWidth(window.COL_SCORE, 62)
        window.table.setColumnWidth(3, 150)
        window.table.setColumnWidth(4, 132)
        window.table.setColumnWidth(5, 220)
        window.table.setColumnWidth(window.COL_PACKAGE, 360)
        window.table.setColumnWidth(7, 220)
        window.table.setColumnWidth(8, 120)
        window.table.setColumnWidth(9, 160)
        window.table.setColumnWidth(window.COL_NOTE, 180)
        window.table.setColumnWidth(12, 220)
        window.table.setColumnWidth(window.COL_VALIDATION, 120)
        for column in (3, 7, 8, 9, window.COL_NOTE, window.COL_REASONS, 12):
            window.table.setColumnHidden(column, True)

        layout.addWidget(window.table, 1)
