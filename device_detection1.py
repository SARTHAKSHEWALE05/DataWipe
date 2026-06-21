#!/usr/bin/env python3
"""
device_detection.py

Cross-platform device detection & classification for secure wiping app.

Usage:
    python device_detection.py        # prints JSON

Optional:
    Import functions from this file into your PySide6 app.

Dependencies:
    pip install psutil PySide6
    adb must be in PATH for Android detection
"""

import platform
import subprocess
import json
import re
import os
from pathlib import Path
import shutil
import psutil     # used for disk partitions / basic info


# ---------- RULESET / DATASET ----------
# Expanded mapping: each device type now has both description + OS-specific commands
# Note: Replace {path} with device path (e.g., /dev/sda) at runtime
RULESET = {
    "HDD": {
        "description": "Multi-pass overwrite (NIST 800-88) — recommended: 3-pass or 7-pass depending on policy",
        "commands": {
            "linux": [
                "shred -v -n 3 -z {path}",          # 3-pass overwrite + final zero
                "dd if=/dev/zero of={path} bs=1M"   # optional full zero fill
            ],
            "windows": [
                'cipher /w:{path}',                 # wipes free space
                'format {path} /P:3 /Q /Y'          # quick format with 3 passes
            ],
            "darwin": [
                "diskutil secureErase 2 {path}"     # 3-pass secure erase on macOS
            ]
        }
    },
    "SSD": {
        "description": "Crypto erase / Firmware Secure Erase (avoid multi-pass overwrite on SSDs)",
        "commands": {
            "linux": [
                "hdparm --user-master u --security-set-pass p {path}",
                "hdparm --user-master u --security-erase p {path}"
            ],
            "windows": [
                "PS> Clear-Disk -Number <disknum> -RemoveData -Confirm:$false"
            ],
            "darwin": [
                "diskutil secureErase 0 {path}"     # single pass overwrite (not ideal but fallback)
            ]
        }
    },
    "NVMe": {
        "description": "NVMe sanitize / Crypto erase (firmware-assisted)",
        "commands": {
            "linux": [
                "nvme format {path} -s1",          # secure erase (crypto)
                "nvme sanitize {path} -a1"         # block erase
            ],
            "windows": [
                "PS> Disable-BitLocker -MountPoint {path}; Remove-Partition -DiskNumber <disknum> -Confirm:$false"
            ],
            "darwin": [
                "diskutil secureErase 0 {path}"
            ]
        }
    },
    "Removable": {
        "description": "Secure erase / blkdiscard (if supported) or full overwrite",
        "commands": {
            "linux": [
                "blkdiscard {path}",                # if supported
                "dd if=/dev/zero of={path} bs=1M"   # fallback overwrite
            ],
            "windows": [
                'format {path} /P:1 /Q /Y'
            ],
            "darwin": [
                "diskutil secureErase 1 {path}"     # single pass overwrite
            ]
        }
    },
    "Android": {
        "description": "Ensure device encryption + Factory reset (destroy encryption key)",
        "commands": {
            "linux": [
                "adb -s {serial} shell recovery --wipe_data",
                "adb -s {serial} shell reboot recovery"
            ],
            "windows": [
                "adb -s {serial} shell recovery --wipe_data"
            ],
            "darwin": [
                "adb -s {serial} shell recovery --wipe_data"
            ]
        }
    },
    "Unknown": {
        "description": "Default: overwrite or manual review",
        "commands": {
            "linux": [
                "dd if=/dev/zero of={path} bs=1M"
            ],
            "windows": [
                "cipher /w:{path}"
            ],
            "darwin": [
                "diskutil secureErase 1 {path}"
            ]
        }
    }
}



# ---------- Utilities ----------
def run_cmd(cmd, shell=False, timeout=8):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=shell, text=True, timeout=timeout)
        return out
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception:
        return ""


def is_tool(name):
    return shutil.which(name) is not None


# ---------- Linux helpers ----------
def _linux_get_rotational(sys_block_name):
    path = Path(f"/sys/block/{sys_block_name}/queue/rotational")
    try:
        return path.read_text().strip() == "1"
    except Exception:
        return None


def detect_linux_block_devices():
    devices = []
    if is_tool("lsblk"):
        out = run_cmd(["lsblk", "-J", "-o", "NAME,MODEL,SERIAL,TYPE,SIZE,ROTA,TRAN,MOUNTPOINT"])
        try:
            ls = json.loads(out)
            for node in ls.get("blockdevices", []):
                # we consider type 'disk' devices
                if node.get("type") != "disk":
                    # some USB sticks are type 'disk' too; partitions are 'part' - we skip partitions
                    continue
                name = node.get("name")
                model = node.get("model") or ""
                serial = node.get("serial") or ""
                size = node.get("size") or ""
                rota = node.get("rota")
                tran = node.get("tran") or ""
                devices.append({
                    "path": f"/dev/{name}",
                    "name": name,
                    "model": model.strip(),
                    "serial": serial.strip(),
                    "size": size,
                    "transport": tran,
                    "rotational_flag": True if rota in ("1", "true", True) else False if rota in ("0", "false", False) else _linux_get_rotational(name)
                })
        except Exception:
            # fallback: parse lsblk -o
            out2 = run_cmd(["lsblk", "-d", "-o", "NAME,MODEL,SERIAL,SIZE,ROTA,TRAN"])
            for line in out2.splitlines()[1:]:
                parts = re.split(r'\s{2,}', line.strip())
                if not parts: continue
                # naive parse
                name = parts[0].split()[0]
                model = parts[1] if len(parts) > 1 else ""
                serial = parts[2] if len(parts) > 2 else ""
                size = parts[3] if len(parts) > 3 else ""
                rota = parts[4] if len(parts) > 4 else None
                devices.append({
                    "path": f"/dev/{name}",
                    "name": name,
                    "model": model.strip(),
                    "serial": serial.strip(),
                    "size": size,
                    "transport": None,
                    "rotational_flag": _linux_get_rotational(name)
                })
    else:
        # Fallback: check /dev entries
        for part in psutil.disk_partitions(all=False):
            # get device base (e.g., /dev/sda)
            dev = re.sub(r'\d+$', '', part.device)
            devices.append({
                "path": dev,
                "name": os.path.basename(dev),
                "model": "",
                "serial": "",
                "size": "",
                "transport": None,
                "rotational_flag": None
            })
    return devices


# ---------- macOS helpers ----------
def detect_macos_block_devices():
    devices = []
    if not is_tool("diskutil"):
        return devices
    out = run_cmd(["diskutil", "list", "-plist"])
    # parsing plist is more involved; simpler approach: use 'diskutil info' on whole disks
    # get disk identifiers from diskutil list
    list_out = run_cmd(["diskutil", "list"])
    disk_ids = []
    for line in list_out.splitlines():
        m = re.match(r"(/dev/disk\d+)", line.strip())
        if m:
            disk_ids.append(m.group(1))
    # fallback: examine /dev entries
    if not disk_ids:
        disk_ids = [d.device for d in psutil.disk_partitions(all=False)]
    for d in disk_ids:
        info = run_cmd(["diskutil", "info", d])
        model = ""
        size = ""
        is_ssd = None
        serial = ""
        for ln in info.splitlines():
            if "Device / Media Name:" in ln:
                model = ln.split(":",1)[1].strip()
            if "Total Size:" in ln and "(" in ln:
                size = ln.split("(")[1].split(")")[0].strip()
            if "Solid State:" in ln:
                is_ssd = "Yes" in ln
            if "Device Identifier:" in ln and not d.endswith(ln.split(":")[1].strip()):
                pass
        devices.append({
            "path": d,
            "name": os.path.basename(d),
            "model": model,
            "serial": serial,
            "size": size,
            "transport": None,
            "rotational_flag": False if is_ssd else True if is_ssd is not None else None
        })
    return devices


# ---------- Windows helpers ----------
def _parse_windows_disk_rows(data):
    rows = []
    if isinstance(data, dict):
        rows = [data]
    elif isinstance(data, list):
        rows = data
    return rows


def detect_windows_block_devices():
    devices = []
    ps_cmd = (
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object Index, Model, SerialNumber, MediaType, Size, Caption | "
        "ConvertTo-Json -Compress"
    )
    out = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    if out.strip():
        try:
            for row in _parse_windows_disk_rows(json.loads(out)):
                model = (row.get("Model") or "").strip()
                serial = (row.get("SerialNumber") or "").strip()
                size = str(row.get("Size") or "").strip()
                caption = (row.get("Caption") or "").strip()
                mtype = (row.get("MediaType") or "").strip()
                index = row.get("Index")
                path = (
                    f"\\\\.\\PHYSICALDRIVE{index}"
                    if index is not None
                    else caption
                )
                low = (model + " " + caption + " " + mtype).lower()
                rot = None
                if "nvme" in low or "mzvl" in low:
                    rot = False
                elif "ssd" in low:
                    rot = False
                elif "hdd" in low or "hard disk drive" in low:
                    rot = True
                elif "removable" in mtype.lower():
                    rot = None
                devices.append({
                    "path": path,
                    "name": caption or path,
                    "model": model,
                    "serial": serial,
                    "size": size,
                    "transport": "usb" if "removable" in mtype.lower() else None,
                    "rotational_flag": rot,
                })
        except Exception:
            pass

    if not devices:
        seen = set()
        for d in psutil.disk_partitions(all=False):
            dev = re.sub(r"\d+$", "", d.device)
            if dev in seen:
                continue
            seen.add(dev)
            devices.append({
                "path": dev,
                "name": os.path.basename(dev),
                "model": "",
                "serial": "",
                "size": "",
                "transport": None,
                "rotational_flag": None,
            })
    return devices


# ---------- Android helper ----------
def detect_android_devices():
    devices = []
    if not is_tool("adb"):
        return devices
    # get list of attached adb devices
    out = run_cmd(["adb", "devices"])
    lines = [l.strip() for l in out.splitlines()]
    found = []
    for ln in lines[1:]:
        if not ln: continue
        if "\t" in ln:
            serial, state = ln.split("\t", 1)
            if state.strip() == "device":
                found.append(serial.strip())
        else:
            # maybe 'device' in same line
            parts = ln.split()
            if parts and parts[-1] == "device":
                found.append(parts[0])
    for serial in found:
        # try to get model and product info
        model = run_cmd(["adb", "-s", serial, "shell", "getprop", "ro.product.model"]).strip()
        brand = run_cmd(["adb", "-s", serial, "shell", "getprop", "ro.product.brand"]).strip()
        size = "N/A"
        devices.append({
            "path": f"adb://{serial}",
            "name": f"{brand} {model}".strip(),
            "model": model or brand,
            "serial": serial,
            "size": size,
            "transport": "usb",
            "rotational_flag": None,
            "android": True
        })
    return devices


# ---------- Classification logic ----------
def classify_device(entry):
    """
    Use heuristics to classify into HDD/SSD/NVMe/Removable/Android/Unknown
    """
    # Android check
    if entry.get("android"):
        dtype = "Android"
        method = RULESET["Android"]
        return dtype, method

    model = (entry.get("model") or "").lower()
    transport = (entry.get("transport") or "").lower() if entry.get("transport") else ""
    rota = entry.get("rotational_flag")

    # NVMe heuristics: model contains 'nvme' or transport nvme
    if "nvme" in model or "nvme" in transport or "mzvl" in model:
        return "NVMe", RULESET["NVMe"]

    # SSD heuristics: model contains ssd, transport is 'sata' + rota flag false, or rota false
    if "ssd" in model or (rota is False and "usb" not in transport):
        return "SSD", RULESET["SSD"]

    # Removable/USB
    if transport and "usb" in transport:
        return "Removable", RULESET["Removable"]

    # HDD heuristics: rota True or model contains 'hdd' or 'hard'
    if rota is True or "hdd" in model or "hard disk" in model:
        return "HDD", RULESET["HDD"]

    # If we have size & model lacking info, attempt to detect rotation via /sys on Linux already attempted
    if rota is None:
        # conservative fallback: unknown
        return "Unknown", RULESET["Unknown"]

    # default fallback
    return "Unknown", RULESET["Unknown"]

def probe_capabilities(device):
    """
    Probe device-specific capabilities.
    Returns a list of supported erase methods for the device.
    """
    system = platform.system().lower()
    path = device.get("path")
    dtype = device.get("detected_type")
    caps = []

    # --- Android ---
    if dtype == "Android":
        out = run_cmd(["adb", "-s", device["serial"], "shell", "getprop", "ro.crypto.state"])
        if "encrypted" in out.lower():
            caps.append("Crypto erase (factory reset removes key)")
        else:
            caps.append("Factory reset only (unencrypted)")
        return caps

    # --- Linux ---
    if system == "linux" and path and path.startswith("/dev/"):
        if dtype in ["HDD", "SSD"]:
            if is_tool("hdparm"):
                out = run_cmd(["hdparm", "-I", path])
                if "supported" in out and "not frozen" in out:
                    if "Enhanced erase" in out:
                        caps.append("Secure Erase Enhanced (hdparm)")
                    else:
                        caps.append("Secure Erase (hdparm)")
        if dtype == "NVMe" and is_tool("nvme"):
            out = run_cmd(["nvme", "id-ctrl", path])
            if "sanitize" in out.lower():
                caps.append("NVMe Sanitize")
        if dtype == "Removable":
            out = run_cmd(["lsblk", "-D", path])
            if "1" in out or "DISCARD" in out.upper():
                caps.append("blkdiscard supported")

    # --- Windows ---
    if system == "windows":
        if dtype in ["HDD", "SSD", "NVMe"]:
            caps.append("Firmware erase check (PowerShell / disk tools)")
        else:
            caps.append("Overwrite only")

    # --- macOS ---
    if system == "darwin":
        if dtype == "SSD":
            caps.append("Diskutil secureErase (1-pass overwrite only)")
        elif dtype == "HDD":
            caps.append("Diskutil secureErase with multi-pass")
        else:
            caps.append("Limited — overwrite only")

    # fallback
    if not caps:
        caps.append("Overwrite only")

    return caps


# modify detect_all_devices() to include capabilities
def detect_all_devices():
    system = platform.system().lower()
    devices = []
    if system == "linux":
        devices = detect_linux_block_devices()
    elif system == "darwin":
        devices = detect_macos_block_devices()
    elif system == "windows":
        devices = detect_windows_block_devices()

    # also Android
    devices.extend(detect_android_devices())

    result = []
    seen_paths = set()
    for d in devices:
        key = (d.get("path") or d.get("serial") or d.get("name"))
        if key in seen_paths:
            continue
        seen_paths.add(key)

        dtype, method = classify_device(d)
        item = {
            "path": d.get("path"),
            "name": d.get("name"),
            "model": d.get("model"),
            "serial": d.get("serial"),
            "size": d.get("size"),
            "transport": d.get("transport"),
            "rotational_flag": d.get("rotational_flag"),
            "detected_type": dtype,
            "recommended_method": method["description"],
            "capabilities": probe_capabilities({
                **d, "detected_type": dtype
            })
        }
        result.append(item)
    return result


# ---------- Optional small PySide6 UI (very small) ----------
def launch_minimal_ui(devices):
    try:
        from PySide6 import QtWidgets, QtGui, QtCore
    except Exception:
        print("PySide6 not installed or not available in this environment. Skipping UI.")
        return

    app = QtWidgets.QApplication([])
    w = QtWidgets.QWidget()
    w.setWindowTitle("Device Detection - One Click Wiper")
    layout = QtWidgets.QVBoxLayout()
    tb = QtWidgets.QTableWidget()
    tb.setColumnCount(6)
    tb.setHorizontalHeaderLabels(["Path", "Model / Name", "Serial", "Size", "Type", "Method"])
    tb.setRowCount(len(devices))
    for i, d in enumerate(devices):
        tb.setItem(i, 0, QtWidgets.QTableWidgetItem(str(d.get("path") or "")))
        tb.setItem(i, 1, QtWidgets.QTableWidgetItem(str(d.get("model") or d.get("name") or "")))
        tb.setItem(i, 2, QtWidgets.QTableWidgetItem(str(d.get("serial") or "")))
        tb.setItem(i, 3, QtWidgets.QTableWidgetItem(str(d.get("size") or "")))
        tb.setItem(i, 4, QtWidgets.QTableWidgetItem(str(d.get("detected_type") or "")))
        tb.setItem(i, 5, QtWidgets.QTableWidgetItem(str(d.get("recommended_method") or "")))
    tb.resizeColumnsToContents()
    layout.addWidget(tb)
    btn = QtWidgets.QPushButton("Close")
    btn.clicked.connect(app.quit)
    layout.addWidget(btn)
    w.setLayout(layout)
    w.resize(900, 300)
    w.show()
    app.exec()


# ---------- If run as script ----------
if __name__ == "__main__":
    devices = detect_all_devices()
    print(json.dumps(devices, indent=2))

