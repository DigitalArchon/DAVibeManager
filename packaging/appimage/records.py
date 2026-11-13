"""Makes each installed package's RECORD say what is in the image. Run by build.sh on the
AppImage's site-packages, once everything the build leaves out of them is gone.

A RECORD lists every file its wheel installed, with the file's hash and size. The build then
takes some of those files away (direct_url.json, the console scripts that name the build's
Python, Pillow's font module and its libraries), and until Nov 2026 the RECORDs still said what
pip had installed. Two things were wrong with that. A RECORD named files that are not there. And
direct_url.json's line carries the hash of that file, which holds the hash of the wheel archive it
was installed from: for the packages build.sh builds itself (PyGObject, pycairo, proxy-tools, DA
Vibe Manager) that archive is made in the build, so the image depended on the bytes of a zip file
that is nowhere in it. A file the build changes (DA Toolkit strips extensions) gets its new hash.
(DA Toolkit's packaging/appimage/records.py, the same code.)

So: the line of a file that is gone is dropped, and the line of a file whose hash or size is no
longer the one listed gets the hash and size the file has. Every other line is written back
as it was, in its place, and a RECORD with nothing to change is not written at all. The result
depends on the RECORD and the files beside it and on nothing else.

    python3 records.py <site-packages>..."""

import base64
import csv
import hashlib
import io
import os
import sys


def _hash(path: str, algorithm: str) -> str:
    """A file's hash as a RECORD writes it: urlsafe base64, no padding."""
    digest = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")


def clean(record: str) -> tuple[int, int]:
    """Bring one RECORD up to date; returns how many lines were dropped and how many were given
    their file's present hash and size. Paths in a RECORD are relative to the folder its
    .dist-info is in ("../../../bin/uvicorn" for a script)."""
    site = os.path.dirname(os.path.dirname(os.path.abspath(record)))
    with open(record, encoding="utf-8", newline="") as f:
        text = f.read()
    rows, dropped, rehashed = [], 0, 0
    for row in csv.reader(io.StringIO(text, newline="")):
        if not row:
            rows.append(row)
            continue
        path = os.path.join(site, row[0])
        if not os.path.lexists(path):
            dropped += 1
            continue
        if len(row) >= 3 and row[1]:            # (its own line, "…/RECORD,,", has neither)
            algorithm = row[1].partition("=")[0]
            now = [f"{algorithm}={_hash(path, algorithm)}", str(os.path.getsize(path))]
            if row[1] != now[0] or (row[2] and row[2] != now[1]):
                row = [row[0], *now, *row[3:]]
                rehashed += 1
        rows.append(row)
    if dropped or rehashed:
        # as pip wrote it: the csv module's default dialect, which ends lines \r\n
        with open(record, "w", encoding="utf-8", newline="") as f:
            csv.writer(f, lineterminator="\r\n" if "\r\n" in text else "\n").writerows(rows)
    return dropped, rehashed


def main(sites: list[str]) -> None:
    records = sorted(os.path.join(site, name, "RECORD") for site in sites for name in os.listdir(site)
                     if name.endswith(".dist-info") and os.path.isfile(os.path.join(site, name, "RECORD")))
    if not records:
        sys.exit(f"records.py: no package's RECORD in {' '.join(sites) or '(no folder given)'}")
    dropped = rehashed = 0
    for record in records:
        gone, changed = clean(record)
        dropped, rehashed = dropped + gone, rehashed + changed
    print(f"RECORD: {dropped} lines of files left out dropped, {rehashed} brought up to date, "
          f"in {len(records)} packages")


if __name__ == "__main__":
    main(sys.argv[1:])
