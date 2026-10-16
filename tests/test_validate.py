"""Unit-Tests für die Eingabe-Validierung (keine externen Tools nötig — CI-sicher)."""
from re_mcp.server import _validate


def test_rejects_empty():
    assert _validate("") is not None
    assert _validate(None) is not None  # type: ignore[arg-type]


def test_rejects_relative_path():
    assert "ABSOLUTEN" in _validate("relativ/pfad")


def test_rejects_missing_file():
    assert "nicht gefunden" in _validate("/nicht/vorhanden/xyz.bin")


def test_rejects_directory(tmp_path):
    assert "regulärer" in _validate(str(tmp_path))


def test_accepts_regular_file(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 100)
    assert _validate(str(f)) is None


def test_suffix_enforced(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    assert _validate(str(f), want_suffix=".apk") is not None
    g = tmp_path / "a.apk"
    g.write_bytes(b"x")
    assert _validate(str(g), want_suffix=".apk") is None


def test_size_cap(tmp_path, monkeypatch):
    from re_mcp import config
    monkeypatch.setattr(config, "MAX_BYTES", 10)
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 100)
    assert "Limit" in _validate(str(f))
