# SimpleBackupandRestore.py
# Portable auto-restore based on manifests produced by the portable Backup tool.
# Expected layout (created by the Backup GUI):
#   d:\SimpleBackupandRestore\<MACHINE>\_backups\Master_YYYYmmdd-HHMMSS\...
#   d:\SimpleBackupandRestore\backup_manifest_Master_YYYYmmdd-HHMMSS.json  (also copied into the backup folder)
#
# Build (example):
#   pyinstaller --noconsole --onefile SimpleBackupandRestore.py
#
# Install:
#   Put the EXE in d:\SimpleBackupandRestore\  (logs and any app files live beside it)
#
from __future__ import annotations
import os, re, json, time, shutil, sys, traceback
from pathlib import Path
from typing import Optional, Tuple, List

# ===================== PORTABLE CONFIG =====================
def app_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "executable"):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

BASE_DIR          = app_dir()                         # everything lives beside the EXE
LOG_FILE          = BASE_DIR / "auto_restore.log"
PREFIX_FILTER     = "Master"                          # case-insensitive, use master prefix when saving backup with the GUI
MANIFEST_GLOB     = "**/backup_manifest_*.json"       # recursive search under BASE_DIR
# ===========================================================

def now_stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")

def log(msg: str):
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8", errors="ignore") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        print(msg, file=sys.stderr)

def sanitize_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_\-]+", "_", name.strip()) or "item"

def to_winlong(p: Path) -> Path:
    s = str(p)
    if os.name == "nt" and not s.startswith("\\\\?\\") and len(s) >= 248:
        if s.startswith("\\\\"):
            s = "\\\\?\\UNC\\" + s[2:]
        else:
            s = "\\\\?\\" + s
    return Path(s)

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def copy_file(src: Path, dst: Path):
    ensure_dir(dst.parent)
    shutil.copy2(src, dst)

def copy_dir_tree(src: Path, dst: Path):
    src = to_winlong(src)
    dst = to_winlong(dst)
    if Path(dst).exists():
        shutil.rmtree(Path(dst))
    ensure_dir(Path(dst))
    for root, _dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        dest_dir = Path(dst) if rel == "." else Path(dst) / rel
        ensure_dir(dest_dir)
        for name in files:
            s = Path(root) / name
            d = dest_dir / name
            copy_file(to_winlong(s), to_winlong(d))

def restore_copy(src: Path, dst: Path):
    """Overwrite-only restore (no snapshots)."""
    src = to_winlong(src); dst = to_winlong(dst)
    if Path(dst).exists():
        if Path(dst).is_dir():
            shutil.rmtree(Path(dst))
        else:
            Path(dst).unlink()
    if Path(src).is_dir():
        copy_dir_tree(Path(src), Path(dst))
    else:
        ensure_dir(Path(dst).parent)
        copy_file(Path(src), Path(dst))

def parse_manifest_timestamp_from_name(name: str) -> Optional[str]:
    m = re.match(r"backup_manifest_[A-Za-z0-9_\-]*_(\d{8}-\d{6})\.json$", name, flags=re.IGNORECASE)
    return m.group(1) if m else None

def extract_prefix_from_manifest_filename(name: str) -> Optional[str]:
    m = re.match(r"backup_manifest_([A-Za-z0-9_\-]+)_(\d{8}-\d{6})\.json$", name, flags=re.IGNORECASE)
    return m.group(1) if m else None

def ts_to_epoch(ts: str) -> float:
    try:
        st = time.strptime(ts, "%Y%m%d-%H%M%S")
        return time.mktime(st)
    except Exception:
        return 0.0

def backup_root_seems_valid(backup_root: Path) -> bool:
    """
    Accept backup roots like:
      <BASE_DIR>\<MACHINE>\_backups\<prefix>_YYYYmmdd-HHMMSS
    """
    try:
        br = backup_root.resolve(strict=False)
        if not str(br).lower().startswith(str(BASE_DIR.resolve(strict=False)).lower()):
            return False
        parts = [p.lower() for p in br.parts]
        if "_backups" not in parts:
            return False
        tail = br.name.lower()
        if not tail.startswith(f"{PREFIX_FILTER.lower()}_"):
            return False
        return True
    except Exception:
        return False

def find_latest_manifest_in_base(base: Path, prefix: str) -> Optional[Path]:
    if not base.exists():
        log(f"[INFO] Manifest base not found: {base}")
        return None

    prefix_l = prefix.lower()
    candidates: List[Tuple[float, Path]] = []

    for f in base.glob(MANIFEST_GLOB):
        name = f.name
        pf_name = extract_prefix_from_manifest_filename(name)
        if pf_name and pf_name.lower() != prefix_l:
            continue

        epoch = 0.0
        json_prefix_ok = True

        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            ts = (data.get("timestamp") or "").strip()
            if ts:
                epoch = ts_to_epoch(ts)
            pf_json = (data.get("prefix") or "").strip()
            if pf_json and pf_json.lower() != prefix_l:
                json_prefix_ok = False
        except Exception:
            pass

        if not json_prefix_ok:
            continue

        if epoch == 0.0:
            ts2 = parse_manifest_timestamp_from_name(name)
            if ts2:
                epoch = ts_to_epoch(ts2)
        if epoch == 0.0:
            try:
                epoch = f.stat().st_mtime
            except Exception:
                epoch = 0.0

        candidates.append((epoch, f))

    if not candidates:
        log(f"[INFO] No manifests under {base} for prefix '{prefix}'")
        return None

    candidates.sort(key=lambda x: x[0], reverse=True)
    latest = candidates[0][1]
    log(f"[INFO] Selected manifest: {latest}")
    return latest

def find_latest_manifest(prefix: str) -> Optional[Path]:
    return find_latest_manifest_in_base(BASE_DIR, prefix)

def restore_from_manifest(manifest_path: Path) -> bool:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"[ERROR] Failed to read manifest {manifest_path}: {e}")
        return False

    backup_root = Path(data.get("backup_root", ""))  # where the data folders live
    if not backup_root.exists():
        log(f"[ERROR] Backup root missing: {backup_root}")
        return False

    if not backup_root_seems_valid(backup_root):
        log(f"[WARN] Backup root not in expected structure: {backup_root} (continuing)")

    items = data.get("items", [])
    if not items:
        log("[WARN] Manifest has no items; nothing to restore.")
        return True

    ok_all = True
    for it in items:
        try:
            kind = it.get("kind")
            orig_src = Path(it.get("src", ""))        # original target path
            token = it.get("backup_subdir") or ""
            name = it.get("name") or orig_src.name

            if not token:
                guess = sanitize_name(orig_src.name)
                token = guess if (backup_root / guess).exists() else ""

            item_data_dir = backup_root / token if token else backup_root
            if not item_data_dir.exists():
                log(f"[SKIP] Missing data dir: {item_data_dir}")
                continue

            if kind == "folder":
                ensure_dir(orig_src)
                for child in item_data_dir.iterdir():
                    restore_copy(child, orig_src / child.name)
                log(f"[RESTORED] folder contents -> {orig_src}")
            else:
                candidate = item_data_dir / name
                if candidate.exists() and candidate.is_file():
                    restore_copy(candidate, orig_src)
                else:
                    files = [p for p in item_data_dir.iterdir() if p.is_file()]
                    if files:
                        restore_copy(files[0], orig_src)
                    else:
                        log(f"[SKIP] No file to restore for {orig_src}")
                        continue
                log(f"[RESTORED] file -> {orig_src}")

        except Exception as e:
            ok_all = False
            log(f"[ERROR] Restore failed for item {it!r}: {e}\n{traceback.format_exc()}")

    return ok_all

def main():
    try:
        log("=== Auto Restore (portable) ===")
        log(f"[INFO] BASE_DIR: {BASE_DIR}")
        latest = find_latest_manifest(PREFIX_FILTER)
        if not latest:
            log("[INFO] No suitable manifest found. Exiting.")
            return 0
        ok = restore_from_manifest(latest)
        if ok:
            log("[SUCCESS] Restore completed successfully.")
            return 0
        else:
            log("[WARN] Restore finished with errors.")
            return 2
    except Exception as e:
        log(f"[FATAL] Unhandled exception: {e}\n{traceback.format_exc()}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
