#!/usr/bin/env python3
"""
certificate_module.py

Generate JSON + PDF certificates for wipe entries, compute canonical SHA-256,
compute PDF SHA-256, create a QR code image containing {cert_id, cert_hash, pdf_hash},
and return certificate metadata for UI/logging.

Dependencies:
    pip install reportlab qrcode pillow pymupdf pyzbar
    system: libzbar (see README)
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import io

import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

# For QR extraction
import fitz  # PyMuPDF
from PIL import Image
from pyzbar.pyzbar import decode as zbar_decode

CERT_DIR = Path("certs")
CERT_DIR.mkdir(parents=True, exist_ok=True)


def _canonical_json(obj) -> str:
    """Return canonical JSON string used for hashing (stable key order, compact)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_pdf_sha256(pdf_path: str) -> str:
    """Return SHA-256 of the raw PDF bytes."""
    p = Path(pdf_path)
    data = p.read_bytes()
    return hashlib.sha256(data).hexdigest()


def generate_qr_image_bytes(payload: str, box_size: int = 6) -> bytes:
    """Return PNG bytes of QR image for given payload (JSON string or URL)."""
    qr = qrcode.QRCode(border=2, box_size=box_size, error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    return bio.read()


def save_json_certificate(cert_obj: dict, out_path: Path):
    out_path.write_text(_canonical_json(cert_obj), encoding="utf-8")


def generate_pdf_certificate(cert_obj: dict, pdf_path: Path, qr_bytes: bytes = None):
    """
    Create a simple PDF certificate with textual fields and embedded QR (if provided).
    """
    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    width, height = A4
    margin = 40
    x = margin
    y = height - margin

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(x, y, "Secure Wipe Certificate")
    y -= 30

    # Metadata
    c.setFont("Helvetica", 11)
    c.drawString(x, y, f"Certificate ID: {cert_obj.get('cert_id')}")
    y -= 16
    c.drawString(x, y, f"Generated At (UTC): {cert_obj.get('generated_at')}")
    y -= 18
    # Cert hash / pdf hash
    c.drawString(x, y, f"Certificate SHA-256: {cert_obj.get('cert_hash', 'N/A')}")
    y -= 16
    c.drawString(x, y, f"PDF SHA-256: {cert_obj.get('pdf_hash', 'N/A')}")
    y -= 22

    # Device details
    c.setFont("Helvetica-Bold", 13)
    c.drawString(x, y, "Device Details:")
    y -= 16
    c.setFont("Helvetica", 11)
    device = cert_obj.get("device", {})
    lines = [
        f"Path: {device.get('path', 'N/A')}",
        f"Model/Name: {device.get('model', device.get('name', 'N/A'))}",
        f"Serial: {device.get('serial', 'N/A')}",
        f"Type: {device.get('type', 'N/A')}",
        f"Size: {device.get('size', 'N/A')}",
        f"Recommended Method: {cert_obj.get('recommended_method', 'N/A')}"
    ]
    for ln in lines:
        c.drawString(x + 10, y, ln)
        y -= 14

    y -= 8
    # Wipe result block
    c.setFont("Helvetica-Bold", 13)
    c.drawString(x, y, "Wipe Result / Log:")
    y -= 16
    c.setFont("Helvetica", 10)
    result = cert_obj.get("wipe_result", "")[:2000]  # cap for PDF
    for line in result.splitlines():
        if y < 120:
            c.showPage()
            y = height - margin
        c.drawString(x + 10, y, line)
        y -= 12

    # QR placement - lower-right
    if qr_bytes:
        try:
            qr_img = ImageReader(io.BytesIO(qr_bytes))
            qr_size = 140
            c.drawImage(qr_img, width - margin - qr_size, margin, qr_size, qr_size)
            c.setFont("Helvetica", 9)
            c.drawString(width - margin - qr_size, margin + qr_size + 6, "Scan to verify certificate")
        except Exception:
            pass

    c.showPage()
    c.save()


def extract_qr_payload_from_pdf(pdf_path: str) -> dict | None:
    """
    Render PDF pages and scan for a QR code. If found, return parsed JSON payload (dict).
    Returns None if no QR or QR is not JSON.
    """
    doc = fitz.open(pdf_path)
    for page in doc:
        pix = page.get_pixmap(dpi=200)
        mode = "RGBA" if pix.alpha else "RGB"
        img = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
        decoded = zbar_decode(img)
        if decoded:
            # Use the first decoded QR
            raw = decoded[0].data.decode("utf-8")
            try:
                return json.loads(raw)
            except Exception:
                return None
    return None


def generate_certificate_from_log_entry(entry: dict, output_dir: str = "certs") -> dict:
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    cert_id = str(uuid.uuid4())
    generated_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"

    cert_obj = {
        "cert_id": cert_id,
        "generated_at": generated_at,
        "device": entry.get("device", {}),
        "wipe_result": entry.get("result", ""),
        "log_entry_hash": entry.get("entry_hash"),
        "recommended_method": entry.get("device", {}).get("type") or entry.get("device", {}).get("detected_type") or "",
        "blockchain_tx": None,
        "cloud_url": None,
        "software": {
            "name": "OneClickWiper",
            "version": "0.1"
        }
    }

    pdf_path = outdir / f"{cert_id}.pdf"

    # Step 1: compute cert_hash (JSON without pdf_hash)
    canonical_tmp = _canonical_json(cert_obj)
    cert_hash = compute_sha256_of_text(canonical_tmp)

    # Step 2: embed QR with cert_id + cert_hash
    qr_payload = json.dumps({"cert_id": cert_id, "cert_hash": cert_hash}, separators=(",", ":"), sort_keys=True)
    qr_bytes = generate_qr_image_bytes(qr_payload)
    generate_pdf_certificate(cert_obj, pdf_path, qr_bytes=qr_bytes)

    # Step 3: compute pdf_hash
    pdf_hash = compute_pdf_sha256(str(pdf_path))

    # Step 4: compute combined_hash = SHA256(cert_hash || pdf_hash)
    combined_input = cert_hash + pdf_hash
    combined_hash = compute_sha256_of_text(combined_input)

    # Step 5: update cert_obj
    cert_obj["cert_hash"] = cert_hash
    cert_obj["pdf_hash"] = pdf_hash
    cert_obj["combined_hash"] = combined_hash

    # Save JSON
    json_path = outdir / f"{cert_id}.json"
    save_json_certificate(cert_obj, json_path)

    # Save QR separately
    qr_path = outdir / f"{cert_id}_qr.png"
    with qr_path.open("wb") as f:
        f.write(qr_bytes)

    return {
        "cert_id": cert_id,
        "cert_hash": cert_hash,
        "pdf_hash": pdf_hash,
        "combined_hash": combined_hash,
        "json_path": str(json_path.resolve()),
        "pdf_path": str(pdf_path.resolve()),
        "qr_path": str(qr_path.resolve()),
        "generated_at": generated_at,
    }




def recompute_cert_hash_from_json_path(json_path: str) -> str:
    """
    Load saved certificate JSON, remove the 'cert_hash' field (which was added after hashing),
    compute canonical JSON the same way generate_certificate_from_log_entry did, and return SHA-256.
    """
    p = Path(json_path)
    obj = json.loads(p.read_text(encoding="utf-8"))
    # Reconstruct the object that was originally hashed (exclude cert_hash)
    obj_no_hash = {k: v for k, v in obj.items() if k != "cert_hash"}
    canonical = _canonical_json(obj_no_hash)
    return compute_sha256_of_text(canonical)
