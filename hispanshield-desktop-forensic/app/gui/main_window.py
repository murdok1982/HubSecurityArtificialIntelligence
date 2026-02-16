import sys
import os
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QListWidget, QPushButton, QFileDialog, QLabel, QSplitter)
from PySide6.QtCore import Qt, QThread, Signal

from app.storage import db
from app.core import ingestor, pipeline
from app.core.models import Case
from app.gui.case_viewer import CaseViewer
from app.reports import pdf_report

class AnalysisThread(QThread):
    finished = Signal(object)
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        
    def run(self):
        # 1. Ingest
        case = ingestor.ingest_file(self.file_path)
        # 2. Pipeline
        processed_case = pipeline.run_analysis_pipeline(case)
        # 3. Generate PDF
        pdf_path = os.path.join(os.path.dirname(processed_case.file_path), f"report_{processed_case.id}.pdf")
        pdf_report.generate_pdf_report(processed_case, pdf_path)
        
        self.finished.emit(processed_case)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Forensics & Analysis Tool")
        self.resize(1000, 700)
        
        # Init DB
        db.init_db()
        
        self.init_ui()
        self.load_cases()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        main_layout = QHBoxLayout()
        splitter = QSplitter(Qt.Horizontal)
        
        # Left Panel: Case List
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        
        self.btn_new = QPushButton("New Analysis / Upload File")
        self.btn_new.setStyleSheet("padding: 10px; font-weight: bold; background-color: #0078d7; color: white;")
        self.btn_new.clicked.connect(self.new_analysis)
        
        self.btn_sync = QPushButton("☁️ Sync Case to Cloud")
        self.btn_sync.setStyleSheet("padding: 10px; background-color: #28a745; color: white;")
        self.btn_sync.clicked.connect(self.sync_to_cloud)
        
        self.case_list = QListWidget()
        self.case_list.itemClicked.connect(self.on_case_selected)
        
        left_layout.addWidget(self.btn_new)
        left_layout.addWidget(self.btn_sync)
        left_layout.addWidget(QLabel("Recent Cases:"))
        left_layout.addWidget(self.case_list)
        left_widget.setLayout(left_layout)
        
        # Right Panel: Viewer
        self.viewer = CaseViewer()
        
        splitter.addWidget(left_widget)
        splitter.addWidget(self.viewer)
        splitter.setStretchFactor(1, 2)
        
        main_layout.addWidget(splitter)
        main_widget.setLayout(main_layout)
        
        # Status Bar
        self.status_label = QLabel("Ready")
        self.statusBar().addWidget(self.status_label)

    def load_cases(self):
        self.case_list.clear()
        cases = db.get_all_cases()
        for c in cases:
            display_text = f"{c['timestamp']} - {c['original_filename']} ({c['status']})"
            self.case_list.addItem(display_text)
            # Store ID in item data? For simplicity, we'll index or use a custom item
            # But QListWidget doesn't easily store extra data without custom item.
            # We'll use user role.
            item = self.case_list.item(self.case_list.count() - 1)
            item.setData(Qt.UserRole, c['id'])

    def on_case_selected(self, item):
        case_id = item.data(Qt.UserRole)
        case_data = db.get_case(case_id)
        if case_data:
            case = Case.from_db_row(case_data)
            self.viewer.load_case(case)

    def new_analysis(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze")
        if not file_path:
            return
            
        self.status_label.setText(f"Analyzing {os.path.basename(file_path)}...")
        self.btn_new.setEnabled(False)
        
        # Run in thread
        self.thread = AnalysisThread(file_path)
        self.thread.finished.connect(self.on_analysis_finished)
        self.thread.start()

    def sync_to_cloud(self):
        item = self.case_list.currentItem()
        if not item:
            self.status_label.setText("Select a case to sync first.")
            return
            
        case_id = item.data(Qt.UserRole)
        case_data = db.get_case(case_id)
        
        if case_data:
            from app.core.cloud_sync import CloudSyncService
            # In a real app, these would come from settings
            sync_service = CloudSyncService("http://localhost:8000", "MuRDoK-Secret-Token")
            
            self.status_label.setText("Syncing to HispanShield Cloud...")
            if sync_service.sync_case(case_data):
                self.status_label.setText("✅ Sync successful!")
            else:
                self.status_label.setText("❌ Sync failed.")

    def on_analysis_finished(self, case):
        self.status_label.setText("Analysis Completed.")
        self.btn_new.setEnabled(True)
        self.load_cases()
        # Select the new case
        # (Simplified: just reload list)
        self.viewer.load_case(case)
