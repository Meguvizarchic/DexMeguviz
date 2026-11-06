"""Create fresh small ZIP fixtures for the trusted-source host checks."""
import argparse
from pathlib import Path
import struct
import warnings
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory; existing files are not replaced")
    root = parser.parse_args().output
    root.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(root / "ordered.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in [("other.txt", b"ignore"), ("classes10.dex", b"ten"),
                            ("classes.dex", b"one"), ("classes2.dex", b"two")]:
            archive.writestr(name, value)
    with zipfile.ZipFile(root / "badcrc.zip", "x") as archive:
        archive.writestr("classes.dex", b"abc")
    bad = root / "badcrc.zip"
    data = bytearray(bad.read_bytes())
    struct.pack_into("<I", data, data.index(b"PK\x01\x02") + 16, 0)
    bad.write_bytes(data)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(root / "duplicate.zip", "x") as archive:
            archive.writestr("classes.dex", b"abc")
            archive.writestr("classes.dex", b"xyz")
    with zipfile.ZipFile(root / "oversize.zip", "x") as archive:
        archive.writestr("classes.dex", b"abcde")
    with zipfile.ZipFile(root / "identical.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("classes.dex", b"one")
        archive.writestr("classes2.dex", b"one")
    with zipfile.ZipFile(root / "resource-only.zip", "x") as archive:
        archive.writestr("assets/a", b"test")


if __name__ == "__main__":
    main()
