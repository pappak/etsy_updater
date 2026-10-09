"""Push SKU Generator label batches into Labelife 5's print history (PM-2410-BT).

The PM-2410-BT CUPS queue is unusable (Zebra EPL2 driver, TSPL firmware), so
labels have to be printed from inside Labelife 5.  The app stores opened
labels as UTF-8-BOM JSON files in Config/HistoryLabels/<YYYYMMDD_HHMMSSmmm>.json
and lists printable entries as absolute paths in Config/PrintHistory — writing
both while the app is closed makes the batch show up under Print History on
the next launch.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Labelife 5 keeps the same Config layout on both platforms, but stores it
# under ~/Library/Application Support on macOS and %APPDATA% on Windows.
CONFIG_DIR = (
    Path.home() / "AppData" / "Roaming" / "QUIN" / "Labelife" / "Config"
    if sys.platform == "win32"
    else Path.home() / "Library" / "Application Support" / "QUIN" / "Labelife" / "Config"
)
HISTORY_DIR = CONFIG_DIR / "HistoryLabels"
PRINT_HISTORY = CONFIG_DIR / "PrintHistory"
IMAGE_STABLE = CONFIG_DIR / "ImageCache"

PROJECTS_DIR = Path(__file__).resolve().parent.parent
SOURCE_FILE = PROJECTS_DIR / "SKU Code Generator" / "labelife-sku-source.json"
ASSET_DIR = PROJECTS_DIR / "LWSG-Sale-Tracker" / "scripts" / "labelife_assets"

# Static sample SKUs inside the source design get rewritten to each batch SKU.
SKU_RE = re.compile(r"^[A-Za-z]{2,6}\d{3,}(\.\d+)?$")
FILL_KEYS = ("sku", "date", "details", "item", "content", "weave", "variant", "colors")
MAX_LABELS = 200


class LabelifeError(RuntimeError):
    """User-facing failure: Labelife open, missing design, bad input."""


def labelife_running() -> bool:
    """True while the Labelife app is up. pgrep matches the macOS bundle name;
    on Windows tasklist only prints a row for a real match (otherwise it emits
    an INFO line), so the image name is looked for in the output."""
    if sys.platform == "win32":
        proc = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Labelife.exe", "/NH"],
            capture_output=True, text=True, errors="replace",
        )
        return "Labelife.exe" in proc.stdout
    return subprocess.run(["pgrep", "-x", "Labelife"], capture_output=True).returncode == 0


def _stamp(i: int) -> str:
    """HistoryLabels filenames are exactly YYYYMMDD_HHMMSSmmm - keep that pattern."""
    t = time.time() + i / 1000.0
    return time.strftime("%Y%m%d_%H%M%S", time.localtime(t)) + f"{int(round((t % 1) * 1000)):03d}"


def _source_skus(source: dict) -> set[str]:
    """SKU-looking strings hard-coded in the design (they are sample data)."""
    found: set[str] = set()
    for control in source.get("controlInfos", []):
        info = control.get("textInfo") or control.get("QRCodeInfo") or control.get("barCodeInfo")
        text = info.get("text") if isinstance(info, dict) else None
        if isinstance(text, str):
            found.update(m.group(0) for m in SKU_RE.finditer(text))
    return found


def _stabilize_images(label: dict) -> list[str]:
    """Keep photo references inside Config/ImageCache (temp folders get swept)."""
    problems = []
    for control in label.get("controlInfos", []):
        info = control.get("photoInfo")
        if not info:
            continue
        src = info.get("imgStr") or ""
        if not src:
            continue
        src_path = Path(src)
        name = src_path.name
        dest = IMAGE_STABLE / name
        if src_path.exists():
            if not str(src_path).startswith(str(IMAGE_STABLE)):
                IMAGE_STABLE.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    shutil.copy2(src_path, dest)
                info["imgStr"] = str(dest)
        elif dest.exists():
            info["imgStr"] = str(dest)
        elif (ASSET_DIR / name).exists():
            IMAGE_STABLE.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ASSET_DIR / name, dest)
            info["imgStr"] = str(dest)
        else:
            problems.append(src)
    return problems


def _fill_label(source: dict, fields: dict, sku: str, static_skus: set[str]) -> tuple[dict, list[str]]:
    label = json.loads(json.dumps(source))
    for key in ("userSaveId", "templateId", "printId", "jsonId"):
        label[key] = ""
    label["labelName"] = f"{sku} - SKU label"
    label["saveTimestamp"] = int(time.time() * 1000)

    for control in label.get("controlInfos", []):
        info = control.get("textInfo") or control.get("QRCodeInfo") or control.get("barCodeInfo")
        if not isinstance(info, dict) or not isinstance(info.get("text"), str):
            continue
        text = info["text"]
        for key, value in fields.items():
            token = "{" + key + "}"
            if token in text:
                text = text.replace(token, value)
        for sample in static_skus - {sku}:
            if sample in text:
                text = text.replace(sample, sku)
        if control.get("type") in ("QRCode", "barCode"):
            if sku:  # QR/barcodes on these labels always carry the batch SKU
                text = sku
        elif SKU_RE.match(text.strip()) and text.strip() != sku:
            text = sku
        info["text"] = text
        if "textLines" in info:
            info["textLines"] = []
    return label, _stabilize_images(label)


def _normalize_entries(raw) -> list[dict]:
    if not isinstance(raw, list) or not raw:
        raise LabelifeError("No labels to send.")
    if len(raw) > MAX_LABELS:
        raise LabelifeError(f"Too many labels in one batch (max {MAX_LABELS}).")
    entries = []
    for index, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            raise LabelifeError(f"Label {index} is malformed.")
        sku = str(entry.get("sku") or "").strip()
        if not sku:
            raise LabelifeError(f"Label {index} has no SKU.")
        fields = {key: str(entry[key]) for key in FILL_KEYS if entry.get(key) not in (None, "")}
        fields["sku"] = sku
        entries.append({"sku": sku, "fields": fields})
    return entries


def _inject(paths: list[Path]) -> None:
    targets = [str(p) for p in paths]
    if PRINT_HISTORY.exists():
        backup = PRINT_HISTORY.with_suffix(".bak-fill")
        if not backup.exists():
            shutil.copy2(PRINT_HISTORY, backup)
        entries = json.loads(PRINT_HISTORY.read_text(encoding="utf-8-sig"))
    else:
        entries = []
    merged = targets + [e for e in entries if e not in set(targets)]
    PRINT_HISTORY.write_text(json.dumps(merged, ensure_ascii=False, indent=4), encoding="utf-8-sig")


def send_labels(raw_entries) -> dict:
    """Fill the source design per entry, write history files, queue for print."""
    if labelife_running():
        raise LabelifeError("Labelife is open — quit Labelife 5, then send again.")
    if not SOURCE_FILE.is_file():
        raise LabelifeError(f"Label design not found: {SOURCE_FILE}")
    try:
        source = json.loads(SOURCE_FILE.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabelifeError(f"Label design could not be read: {exc}") from exc

    entries = _normalize_entries(raw_entries)
    static_skus = _source_skus(source)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    warnings: list[str] = []
    for index, entry in enumerate(entries):
        label, problems = _fill_label(source, entry["fields"], entry["sku"], static_skus)
        warnings.extend(f"{entry['sku']}: missing image {p}" for p in problems)
        path = HISTORY_DIR / f"{_stamp(index)}.json"
        path.write_text(json.dumps(label, ensure_ascii=False, indent=2), encoding="utf-8-sig")
        written.append(path)

    _inject(written)
    return {
        "created": len(written),
        "labels": [p.name for p in written],
        "warnings": warnings,
    }
