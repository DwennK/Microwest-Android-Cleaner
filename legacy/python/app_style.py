APP_STYLESHEET = """
QMainWindow { background: #f4f6f8; }
QLabel#Title { font-size: 24px; font-weight: 700; color: #111827; }
QLabel#Subtitle { font-size: 13px; color: #64748b; }
QLabel#StatusPill { color: #334155; background: #e8eef5; border: 1px solid #ccd6e3; border-radius: 6px; padding: 7px 10px; }
QLabel#Muted { color: #5f6b7a; }
QLabel#SectionTitle { font-size: 16px; font-weight: 700; color: #172033; }
QLabel#MetricLabel { color: #1f2937; font-weight: 700; background: #eef4fb; border: 1px solid #d7e2ee; border-radius: 6px; padding: 6px 9px; }
QLabel#StepCardTitle { color: #111827; font-weight: 700; }
QLabel#WorkflowStep { color: #516070; background: #edf2f7; border: 1px solid #d4dde8; border-radius: 6px; padding: 6px 10px; font-weight: 700; }
QLabel#WorkflowStepActive { color: #0f172a; background: #e0f2fe; border: 1px solid #38bdf8; border-radius: 6px; padding: 6px 10px; font-weight: 700; }
QLabel#WorkflowStepDone { color: #14532d; background: #dcfce7; border: 1px solid #86efac; border-radius: 6px; padding: 6px 10px; font-weight: 700; }
QWidget#ActionBanner { background: #f8fafc; border: 1px solid #d7e2ee; border-radius: 8px; }
QWidget#ActionBanner[state="risk"] { background: #fff1f2; border-color: #fda4af; }
QWidget#ActionBanner[state="review"] { background: #fffbeb; border-color: #fcd34d; }
QWidget#ActionBanner[state="ok"] { background: #ecfdf5; border-color: #86efac; }
QLabel#ActionBannerTitle { color: #111827; font-size: 15px; font-weight: 700; }
QLabel#ActionBannerBody { color: #475569; }
QTabWidget#WorkspaceTabs::pane { border: 1px solid #d4dde8; background: white; border-radius: 0; top: -1px; }
QTabBar::tab { min-width: 92px; padding: 10px 14px; border: 1px solid #d4dde8; background: #edf2f7; margin-right: 2px; color: #1f2937; }
QTabBar::tab:selected { background: white; border-bottom-color: white; font-weight: 700; color: #111827; }
QTabBar::tab:hover { background: #f8fafc; }
QGroupBox { border: 1px solid #d8dee8; border-radius: 6px; margin-top: 10px; padding: 12px; background: #ffffff; }
QGroupBox#SidebarGroup { background: #fbfcfe; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QPushButton { padding: 8px 12px; border: 1px solid #b7c2d0; border-radius: 6px; background: #ffffff; color: #111827; }
QPushButton:hover { background: #eef5ff; border-color: #8fb2df; }
QPushButton#PrimaryButton { background: #1d4ed8; border-color: #1d4ed8; color: white; font-weight: 700; }
QPushButton#PrimaryButton:hover { background: #1e40af; border-color: #1e40af; }
QPushButton#DangerButton { color: #991b1b; border-color: #e1a1a1; background: #fff7f7; }
QPushButton#DangerButton:hover { background: #fee2e2; border-color: #dc2626; }
QPushButton:disabled { color: #8492a6; background: #eef2f7; }
QLineEdit, QComboBox { padding: 7px; border: 1px solid #b9c2cf; border-radius: 6px; background: white; }
QLineEdit:focus, QComboBox:focus { border-color: #2563eb; }
QTableWidget { background: white; border: 1px solid #d8dee8; gridline-color: #edf1f5; selection-background-color: #2563eb; selection-color: white; }
QTableWidget { alternate-background-color: #f9fbfd; }
QTextEdit { background: white; border: 1px solid #d8dee8; border-radius: 6px; padding: 8px; }
QHeaderView::section { background: #edf2f7; padding: 7px; border: 0; border-right: 1px solid #d8dee8; font-weight: 700; color: #1f2937; }
"""
