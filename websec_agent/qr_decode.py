"""Decode a QR code image to the URL (or other text) it encodes - so a
screenshot or photo of a QR code (quishing: a malicious QR code pasted
over a legitimate one on a parking meter, invoice, poster, etc.) can be
fed into the same analyze_webpage/analyze_html pipeline as any other URL.

Uses OpenCV's built-in QRCodeDetector (opencv-python-headless) rather
than pyzbar, to avoid needing a system-level zbar library installed
alongside the Python package.
"""
from __future__ import annotations


class QRDecodeError(Exception):
    pass


def decode_qr_file(path: str) -> str:
    """Returns the raw decoded string (a URL, or whatever text the QR
    code actually encodes - QR codes aren't always URLs). Raises
    QRDecodeError if the file isn't a readable image or contains no
    detectable QR code, RuntimeError if opencv isn't installed."""
    try:
        import cv2
    except ImportError as exc:
        raise RuntimeError("QR decoding requires: pip install -r requirements-qr.txt") from exc

    image = cv2.imread(path)
    if image is None:
        raise QRDecodeError(f"could not read image file: {path}")

    detector = cv2.QRCodeDetector()
    data, _points, _ = detector.detectAndDecode(image)
    if not data:
        raise QRDecodeError("no QR code found in the image")
    return data
