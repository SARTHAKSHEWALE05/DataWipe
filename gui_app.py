#!/usr/bin/env python3
"""
gui_app.py
Secure Data Wiping GUI with admin/root elevation on live wipe only.
"""

import sys
import os
import platform
import ctypes
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QPushButton,
    QTextEdit,
    QLabel,
    QListWidget,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QFileDialog,
    QInputDialog,
)

from device_detection1 import detect_all_devices
from wiper import wipe_device
from logger_module import log_wipe, load_logs, attach_certificate_to_entry
import certificate_module as cert_mod
import blockchain_module as chain_mod


def is_admin():
    system = platform.system().lower()
    if system == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    return os.geteuid() == 0


def relaunch_as_admin():
    """Attempt to relaunch the current script with admin privileges."""
    system = platform.system().lower()
    if system == "windows":
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)
    os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


def ensure_admin_for_live_wipe(parent) -> bool:
    """Prompt for elevation only when a live wipe is requested."""
    if is_admin():
        return True

    answer = QMessageBox.question(
        parent,
        "Administrator Required",
        "A live wipe requires administrator/root privileges.\n\n"
        "Relaunch the app with elevated rights now?",
        QMessageBox.Yes | QMessageBox.No,
    )
    if answer == QMessageBox.Yes:
        relaunch_as_admin()
    return False


def format_timestamp(raw_ts: str) -> str:
    try:
        if raw_ts.endswith("Z"):
            raw_ts = raw_ts[:-1]
        dt = datetime.fromisoformat(raw_ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw_ts


class DeviceWiperApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Data Wiping - Device Detection")
        self.devices = []

        layout = QVBoxLayout()
        self.label = QLabel("Click below to detect connected storage devices:")
        layout.addWidget(self.label)

        self.detect_button = QPushButton("Detect Devices")
        self.detect_button.clicked.connect(self.show_devices)
        layout.addWidget(self.detect_button)

        self.device_list = QListWidget()
        layout.addWidget(self.device_list)

        self.wipe_button = QPushButton("Wipe Selected Device (Dry Run)")
        self.wipe_button.clicked.connect(lambda: self.wipe_selected_device(dry_run=True))
        self.wipe_button.setEnabled(False)
        layout.addWidget(self.wipe_button)

        self.live_wipe_button = QPushButton("Wipe Selected Device (LIVE — Destructive)")
        self.live_wipe_button.clicked.connect(lambda: self.wipe_selected_device(dry_run=False))
        self.live_wipe_button.setEnabled(False)
        layout.addWidget(self.live_wipe_button)

        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(5)
        self.logs_table.setHorizontalHeaderLabels(
            ["Timestamp", "Device Path", "Type", "Result", "Hash"]
        )
        header = self.logs_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        layout.addWidget(self.logs_table, stretch=2)

        self.view_logs_button = QPushButton("Load Wipe Logs")
        self.view_logs_button.clicked.connect(self.load_logs_into_box)
        layout.addWidget(self.view_logs_button)

        self.logs_label = QLabel("Wipe Logs (Detailed View):")
        layout.addWidget(self.logs_label)
        self.logs_output_box = QTextEdit()
        self.logs_output_box.setReadOnly(True)
        self.logs_output_box.setMinimumHeight(150)
        layout.addWidget(self.logs_output_box, stretch=1)

        self.output_label = QLabel("Current Device Details & Wipe Results:")
        layout.addWidget(self.output_label)
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setMinimumHeight(200)
        layout.addWidget(self.output_box, stretch=1)

        self.verify_button = QPushButton("Verify Certificate")
        self.verify_button.clicked.connect(self.verify_certificate)
        layout.addWidget(self.verify_button)

        self.setLayout(layout)

        if chain_mod.is_blockchain_configured():
            self.output_box.append("[INFO] Blockchain verification is enabled.")
        else:
            self.output_box.append(
                "[INFO] Blockchain not configured — certificates and dry runs still work."
            )

    def verify_certificate(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Certificate PDF", "certs/", "PDF Files (*.pdf)"
        )
        if not path:
            return

        self.output_box.append(f"\n[VERIFY] Selected PDF: {path}")

        qr_payload = cert_mod.extract_qr_payload_from_pdf(path)
        if not qr_payload:
            QMessageBox.critical(self, "Verification Error", "No QR payload found.")
            return

        cert_id = qr_payload.get("cert_id")
        cert_hash = qr_payload.get("cert_hash")
        if not cert_id or not cert_hash:
            QMessageBox.critical(self, "Verification Error", "QR missing cert_id or cert_hash.")
            return

        self.output_box.append(f"[VERIFY] QR payload: cert_id={cert_id}, cert_hash={cert_hash}")

        pdf_hash = cert_mod.compute_pdf_sha256(path)
        combined_local = cert_mod.compute_sha256_of_text(cert_hash + pdf_hash)

        if not chain_mod.is_blockchain_configured():
            QMessageBox.information(
                self,
                "Local Verification Only",
                "Blockchain is not configured.\n"
                "QR payload and PDF hash were read successfully, but on-chain verification was skipped.",
            )
            self.output_box.append("[VERIFY] Local PDF/QR check OK; blockchain skipped.")
            return

        try:
            ok, combined_onchain = chain_mod.verify_certificate(cert_id, combined_local)
        except Exception as e:
            QMessageBox.critical(self, "Verification Error", f"Blockchain lookup failed: {e}")
            return

        if not ok:
            QMessageBox.critical(
                self,
                "Verification Failed",
                f"On-chain hash mismatch!\nExpected: {combined_onchain}\nGot: {combined_local}",
            )
            return

        QMessageBox.information(
            self, "Verification Success", f"Certificate verified!\ncert_id: {cert_id}"
        )
        self.output_box.append(f"[VERIFY] Blockchain + PDF verification success for {cert_id}")

    def show_devices(self):
        self.output_box.clear()
        self.device_list.clear()
        self.devices = detect_all_devices()

        if not self.devices:
            self.output_box.append("No devices detected.")
            self.wipe_button.setEnabled(False)
            self.live_wipe_button.setEnabled(False)
            return

        for i, dev in enumerate(self.devices):
            entry = (
                f"{i}: {dev.get('path', '')} | "
                f"{dev.get('model') or dev.get('name', '')} | "
                f"{dev.get('detected_type', 'Unknown')}"
            )
            self.device_list.addItem(entry)
            self.output_box.append(
                "------------------------------------------------------------------------------------\n"
                f"Path: {dev.get('path', '')}\n"
                f"Name/Model: {dev.get('model') or dev.get('name', '')}\n"
                f"Serial: {dev.get('serial', '')}\n"
                f"Size: {dev.get('size', '')}\n"
                f"Detected Type: {dev.get('detected_type', 'Unknown')}\n"
                f"Recommended Method: {dev.get('recommended_method', 'N/A')}\n"
                f"Capabilities: {', '.join(dev.get('capabilities', []))}\n"
                "--------------------------------------------------------------------------------------"
            )

        self.wipe_button.setEnabled(True)
        self.live_wipe_button.setEnabled(True)

    def wipe_selected_device(self, dry_run=True):
        selected = self.device_list.currentRow()
        if selected < 0 or selected >= len(self.devices):
            QMessageBox.warning(self, "No Selection", "Please select a device to wipe.")
            return

        dev = self.devices[selected]
        mode_label = "Dry Run" if dry_run else "LIVE WIPE"

        confirm = QMessageBox.question(
            self,
            f"Confirm {mode_label}",
            f"Are you sure you want to {'simulate' if dry_run else 'PERMANENTLY ERASE'}:\n\n"
            f"{dev.get('path')} ({dev.get('detected_type')})?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm == QMessageBox.No:
            return

        if not dry_run:
            typed, ok = QInputDialog.getText(
                self,
                "Confirm LIVE Wipe",
                "Type ERASE to confirm permanent data destruction:",
            )
            if not ok or typed.strip().upper() != "ERASE":
                QMessageBox.information(self, "Cancelled", "Live wipe cancelled.")
                return
            if not ensure_admin_for_live_wipe(self):
                return

        self.output_box.append(f"\n--- Wiping {dev.get('path')} ({mode_label}) ---")
        result = wipe_device(dev, confirm=False, dry_run=dry_run)
        self.output_box.append(result)

        entry = log_wipe(dev, result, dry_run=dry_run)
        formatted_ts = format_timestamp(entry["timestamp"])
        cert_meta = None

        try:
            cert_meta = cert_mod.generate_certificate_from_log_entry(entry, output_dir="certs")
            attach_ok = attach_certificate_to_entry(entry["entry_hash"], cert_meta)
            if attach_ok:
                self.output_box.append(f"\n[CERT GENERATED] ID: {cert_meta['cert_id']}")
                self.output_box.append(f"PDF: {cert_meta['pdf_path']}")
                self.output_box.append(f"JSON: {cert_meta['json_path']}")
                self.output_box.append(f"QR: {cert_meta['qr_path']}")
            else:
                self.output_box.append("\n[WARN] Certificate generated but failed to attach to log.")
        except Exception as e:
            self.output_box.append(f"\n[ERROR] Failed to generate certificate: {e}")

        if cert_meta:
            self.output_box.append(
                f"\n[LOGGED] Timestamp: {formatted_ts} | Certificate Hash: {cert_meta['cert_hash']}"
            )
            if chain_mod.is_blockchain_configured():
                try:
                    tx_hash = chain_mod.store_certificate_hash(
                        cert_meta["cert_id"], cert_meta["combined_hash"]
                    )
                    if tx_hash:
                        self.output_box.append(f"[BLOCKCHAIN] Cert hash stored on-chain. Tx: {tx_hash}")
                    else:
                        self.output_box.append("[BLOCKCHAIN] Failed to store certificate on-chain.")
                except Exception as e:
                    self.output_box.append(f"[ERROR] Blockchain store failed: {e}")
            else:
                self.output_box.append("[BLOCKCHAIN] Skipped — not configured.")
        else:
            self.output_box.append(
                f"\n[LOGGED] Timestamp: {formatted_ts} | Entry Hash: {entry['entry_hash']}"
            )

        row = self.logs_table.rowCount()
        self.logs_table.insertRow(row)
        self.logs_table.setItem(row, 0, QTableWidgetItem(formatted_ts))
        self.logs_table.setItem(row, 1, QTableWidgetItem(entry["device"]["path"]))
        self.logs_table.setItem(row, 2, QTableWidgetItem(entry["device"]["type"]))
        preview = entry["result"][:40] + ("..." if len(entry["result"]) > 40 else "")
        self.logs_table.setItem(row, 3, QTableWidgetItem(preview))
        display_hash = cert_meta["cert_hash"] if cert_meta else entry["entry_hash"]
        self.logs_table.setItem(row, 4, QTableWidgetItem(display_hash))

    def load_logs_into_box(self):
        logs = load_logs()
        self.logs_output_box.clear()
        if not logs:
            self.logs_output_box.append("No logs found.")
            return

        for idx, entry in enumerate(logs, start=1):
            device = entry.get("device", {})
            timestamp = format_timestamp(entry.get("timestamp", ""))
            self.logs_output_box.append(
                f"Log {idx}:\n"
                f"Timestamp: {timestamp}\n"
                f"Device Path: {device.get('path', 'N/A')}\n"
                f"Type: {device.get('type') or device.get('detected_type', 'Unknown')}\n"
                f"Result: {entry.get('result', '')}\n"
                f"Entry Hash: {entry.get('entry_hash', '')}\n"
                f"Certificate Hash: {entry.get('cert_hash', '')}\n"
                "------------------------------------------------------------\n"
            )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DeviceWiperApp()
    window.resize(700, 600)
    window.show()
    sys.exit(app.exec())
