"""Tests for QR code decoding. Generates a real QR code image to decode
(via the `qrcode` package, dev-only) rather than only mocking cv2 - the
thing worth verifying is that a real QR image round-trips correctly."""
import pytest

cv2 = pytest.importorskip("cv2", reason="requires requirements-qr.txt")
qrcode = pytest.importorskip("qrcode", reason="dev-only, for generating a real test QR image")

from websec_agent import qr_decode as qr


def _make_qr_image(path, data: str):
    img = qrcode.make(data)
    img.save(path)


def test_decodes_a_real_qr_code(tmp_path):
    path = tmp_path / "qr.png"
    _make_qr_image(str(path), "https://wetransfer-smoky.vercel.app/")
    assert qr.decode_qr_file(str(path)) == "https://wetransfer-smoky.vercel.app/"


def test_decodes_non_url_content(tmp_path):
    # QR codes aren't always URLs - plain text, vCards, Wi-Fi credentials,
    # etc. are all valid payloads the caller has to handle separately.
    path = tmp_path / "qr.png"
    _make_qr_image(str(path), "just some plain text")
    assert qr.decode_qr_file(str(path)) == "just some plain text"


def test_raises_when_no_qr_code_in_image(tmp_path):
    import numpy as np

    path = tmp_path / "blank.png"
    blank = np.ones((200, 200, 3), dtype="uint8") * 255
    cv2.imwrite(str(path), blank)

    with pytest.raises(qr.QRDecodeError, match="no QR code"):
        qr.decode_qr_file(str(path))


def test_raises_for_unreadable_file(tmp_path):
    path = tmp_path / "not_an_image.txt"
    path.write_text("hello")

    with pytest.raises(qr.QRDecodeError, match="could not read"):
        qr.decode_qr_file(str(path))
