from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, 
                               QTextEdit, QGroupBox, QHBoxLayout, QScrollArea, QListWidget, QMessageBox)
from PySide6.QtCore import Qt
from PySide6.QtGui import QClipboard, QGuiApplication
import os
import subprocess
import webbrowser

from app.core.models import Case
from app.reports import export_agents, pdf_report
from app.config import (AGENT_URL_REVERSING, AGENT_URL_INTEL, 
                       AGENT_URL_HOST_GLC, AGENT_URL_INDUSTRIAL)

class CaseViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.current_case = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Info Group
        self.info_group = QGroupBox("Case Information")
        info_layout = QVBoxLayout()
        self.lbl_filename = QLabel("Filename: ")
        self.lbl_filetype = QLabel("Type: ")
        self.lbl_hashes = QLabel("Hashes: ")
        self.lbl_risk = QLabel("Risk Score: ")
        info_layout.addWidget(self.lbl_filename)
        info_layout.addWidget(self.lbl_filetype)
        info_layout.addWidget(self.lbl_hashes)
        info_layout.addWidget(self.lbl_risk)
        self.info_group.setLayout(info_layout)
        layout.addWidget(self.info_group)
        
        # Analysis Results
        self.results_group = QGroupBox("Analysis Details")
        results_layout = QVBoxLayout()
        self.txt_details = QTextEdit()
        self.txt_details.setReadOnly(True)
        results_layout.addWidget(self.txt_details)
        self.results_group.setLayout(results_layout)
        layout.addWidget(self.results_group)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        
        self.btn_open_pdf = QPushButton("Open PDF Report")
        self.btn_open_pdf.clicked.connect(self.open_pdf)
        btn_layout.addWidget(self.btn_open_pdf)
        
        layout.addLayout(btn_layout)
        
        # Agent Buttons
        agent_layout = QHBoxLayout()
        
        self.btn_reversing = QPushButton("Reversing Expert\n(Copy & Open)")
        self.btn_reversing.clicked.connect(lambda: self.process_agent("reversing", AGENT_URL_REVERSING))
        
        self.btn_intel = QPushButton("Cyber Intel\n(Copy & Open)")
        self.btn_intel.clicked.connect(lambda: self.process_agent("intel", AGENT_URL_INTEL))
        
        self.btn_host = QPushButton("Host Defense (GLC)\n(Copy & Open)")
        self.btn_host.clicked.connect(lambda: self.process_agent("host", AGENT_URL_HOST_GLC))

        self.btn_industrial = QPushButton("Cyber Industrial\n(Copy & Open)")
        self.btn_industrial.clicked.connect(lambda: self.process_agent("industrial", AGENT_URL_INDUSTRIAL))
        
        agent_layout.addWidget(self.btn_reversing)
        agent_layout.addWidget(self.btn_intel)
        agent_layout.addWidget(self.btn_host)
        agent_layout.addWidget(self.btn_industrial)
        
        layout.addLayout(agent_layout)
        
        self.setLayout(layout)

    def load_case(self, case: Case):
        self.current_case = case
        self.lbl_filename.setText(f"Filename: {case.original_filename}")
        self.lbl_filetype.setText(f"Type: {case.file_type} | Size: {case.file_size} bytes")
        self.lbl_hashes.setText(f"MD5: {case.md5}\nSHA256: {case.sha256}")
        self.lbl_risk.setText(f"Risk Score: {case.risk_score} / 100")
        
        # Format details text
        details = "STATIC ANALYSIS:\n"
        static = case.analysis_results.get("static", {})
        details += f"Entropy: {static.get('entropy', 'N/A')}\n"
        
        pe = static.get("pe_info", {})
        if pe and "error" not in pe:
            details += f"Imphash: {pe.get('imphash')}\n"
            details += "Sections:\n"
            for s in pe.get("sections", []):
                details += f"  {s['name']} (Ent: {s['entropy']:.2f})\n"

        details += "\nYARA MATCHES:\n"
        yara_res = case.analysis_results.get("yara", {})
        matches = yara_res.get("matches", [])
        if matches:
            for m in matches:
                details += f"- Rule: {m['rule']}\n"
        else:
            details += "No matches found.\n"
                
        details += "\nDYNAMIC ANALYSIS:\n"
        dynamic = case.analysis_results.get("dynamic", {})
        behavior = dynamic.get("behavior", {})
        if behavior:
            details += f"Processes: {behavior.get('processes')}\n"
            details += f"Network: {behavior.get('network')}\n"
            
        self.txt_details.setText(details)

    def open_pdf(self):
        if not self.current_case:
            return
            
        pdf_path = os.path.join(os.path.dirname(self.current_case.file_path), f"report_{self.current_case.id}.pdf")
        if not os.path.exists(pdf_path):
             QMessageBox.warning(self, "Error", "PDF Report not found.")
             return
             
        # Open default viewer
        if os.name == 'nt':
            os.startfile(pdf_path)
        else:
            subprocess.call(('xdg-open', pdf_path))

    def process_agent(self, p_type, url):
        if not self.current_case:
            return
            
        text = ""
        if p_type == "reversing":
            text = export_agents.build_reversing_expert_prompt(self.current_case)
        elif p_type == "intel":
            text = export_agents.build_cyber_intel_prompt(self.current_case)
        elif p_type == "host":
            text = export_agents.build_host_countermeasures_prompt(self.current_case)
        elif p_type == "industrial":
            text = export_agents.build_cyber_industrial_prompt(self.current_case)
            
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(text)
        
        # Open Browser
        webbrowser.open(url)
