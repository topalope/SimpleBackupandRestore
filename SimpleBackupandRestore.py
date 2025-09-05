"""
Simple Backup & Restore (GUI) — Portable, overwrite-only

Behavior:
- Backup: select files/folders → saved into timestamped folders under
    <DEST>\<MACHINE>\_backups\<PREFIX_>YYYYmmdd-HHMMSS\
  Each selected item is copied into its own subfolder inside the backup root
  (folders copy *contents*, files copy as-is).

- Manifest: backup_manifest_<PREFIX_>YYYYmmdd-HHMMSS.json is written atomically
  BESIDE THE EXE (PROGRAM_ROOT) **and also copied into the backup folder**.

- Restore: choose a manifest (auto-refresh list), restore to original or to a
  custom folder. Restores are OVERWRITE-ONLY (no pre-restore snapshots).

Build (example):
  pyinstaller --noconsole --onefile simple_backup_restore_portable.py
Place the EXE in: D:\SimpleBackupandRestore\
"""

from __future__ import annotations
import os, re, json, time, shutil, threading, sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Tuple, Callable

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---------------------------- App folder / Constants ----------------------------

def app_dir() -> Path:
    """
    Folder BESIDE the running executable (PyInstaller) or this script.
    All app artifacts (config, manifests) live here.
    """
    try:
        if getattr(sys, "frozen", False) and hasattr(sys, "executable"):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent
    except Exception:
        return Path(os.getcwd()).resolve()

PROGRAM_ROOT = app_dir()             # app-managed files live here (next to the EXE)
PROGRAM_ROOT.mkdir(parents=True, exist_ok=True)

CONFIG_FILE = PROGRAM_ROOT / "config.json"
MANIFEST_DIR = PROGRAM_ROOT          # keep manifests right next to EXE

# ---------------------------- Helpers ----------------------------

def now_stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")

def clean_path(p: str) -> str:
    if not p:
        return ""
    s = p.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    s = os.path.expandvars(os.path.expanduser(s))
    if re.fullmatch(r"[A-Za-z]:", s):
        s = s + "\\"
    try:
        s = os.path.normpath(s)
    except Exception:
        pass
    return s

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def sanitize_name(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_\-]+", "_", name.strip())
    return s or "item"

def is_subpath(child: Path, parent: Path) -> bool:
    """True if child is inside parent (after resolving)."""
    try:
        child = child.resolve(strict=False)
        parent = parent.resolve(strict=False)
        return parent in child.parents
    except Exception:
        return False

def atomic_write_json(path: Path, data: dict) -> None:
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def ts_to_readable(ts: str) -> Tuple[float, str]:
    """
    Convert YYYYmmdd-HHMMSS to (epoch_seconds, 'YYYY-MM-DD HH:MM:SS').
    If parse fails, returns (0.0, ts).
    """
    try:
        st = time.strptime(ts, "%Y%m%d-%H%M%S")
        epoch = time.mktime(st)  # local time
        return epoch, time.strftime("%Y-%m-%d %H:%M:%S", st)
    except Exception:
        return 0.0, ts

def to_winlong(p: Path) -> Path:
    """
    Add Windows long path prefix when needed.
    """
    s = str(p)
    if os.name == "nt" and not s.startswith("\\\\?\\") and len(s) >= 248:
        if s.startswith("\\\\"):  # UNC
            s = "\\\\?\\UNC\\" + s[2:]
        else:
            s = "\\\\?\\" + s
    return Path(s)

# ---------------------------- Copying primitives ----------------------------

def copy_file(src: Path, dst: Path) -> None:
    ensure_dir(dst.parent)
    shutil.copy2(src, dst)

def copy_dir_tree(src: Path, dst: Path, bump: Optional[Callable[[], None]] = None,
                  cancel_flag: Optional[Callable[[], bool]] = None) -> None:
    """
    Copy entire directory src -> dst, preserving metadata for files (copy2),
    replacing existing dst if present. Calls bump() per file for progress,
    can be canceled via cancel_flag().
    """
    src = to_winlong(src)
    dst = to_winlong(dst)
    if Path(dst).exists():
        shutil.rmtree(Path(dst))
    ensure_dir(Path(dst))

    for root, _dirs, files in os.walk(src):
        if cancel_flag and cancel_flag():
            break
        rel = os.path.relpath(root, src)
        dest_dir = Path(dst) if rel == "." else Path(dst) / rel
        ensure_dir(dest_dir)
        for name in files:
            if cancel_flag and cancel_flag():
                break
            s = Path(root) / name
            d = dest_dir / name
            copy_file(to_winlong(s), to_winlong(d))
            if bump:
                bump()

def copy_folder_contents(src_dir: Path, dst_dir: Path, bump: Optional[Callable[[], None]] = None,
                         cancel_flag: Optional[Callable[[], bool]] = None) -> None:
    """
    Copy the *contents* of src_dir into dst_dir.
    If a child exists at destination, it is replaced.
    """
    src_dir = to_winlong(src_dir)
    dst_dir = to_winlong(dst_dir)
    ensure_dir(dst_dir)
    for child in Path(src_dir).iterdir():
        if cancel_flag and cancel_flag():
            break
        target = Path(dst_dir) / child.name
        if child.is_dir():
            if target.exists():
                shutil.rmtree(target)
            copy_dir_tree(child, target, bump=bump, cancel_flag=cancel_flag)
        else:
            copy_file(child, target)
            if bump:
                bump()

def count_files_for_progress(path: Path) -> int:
    path = Path(path)
    if path.is_dir():
        total = 0
        for _root, _dirs, files in os.walk(path):
            total += len(files)
        return max(total, 1)
    return 1

def backup_item_to_subdir(src: Path, item_subdir: Path,
                          bump: Optional[Callable[[], None]] = None,
                          cancel_flag: Optional[Callable[[], bool]] = None) -> Tuple[bool, str]:
    """
    Copy the selected item into its dedicated subdir in the backup root.
    - For folders: copy *contents* of folder into subdir (no extra layer).
    - For files: copy the file into subdir.
    """
    try:
        ensure_dir(item_subdir)
        if src.is_dir():
            copy_folder_contents(src, item_subdir, bump=bump, cancel_flag=cancel_flag)
            return True, f"folder->contents into {item_subdir}"
        else:
            copy_file(to_winlong(src), to_winlong(item_subdir / src.name))
            if bump:
                bump()
            return True, f"file -> {item_subdir / src.name}"
    except Exception as e:
        return False, str(e)

def restore_copy(src: Path, dst: Path, overwrite: bool = True):
    """
    Replace dst with src (file or folder) WITHOUT snapshots.
    """
    src = to_winlong(src)
    dst = to_winlong(dst)

    if Path(dst).exists() and overwrite:
        if Path(dst).is_dir():
            shutil.rmtree(Path(dst))
        else:
            Path(dst).unlink()

    if Path(src).is_dir():
        copy_dir_tree(Path(src), Path(dst))
    else:
        ensure_dir(Path(dst).parent)
        copy_file(Path(src), Path(dst))

# ---------------------------- Config ----------------------------

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_config(new_cfg: dict):
    try:
        cfg = load_config()
        cfg.update(new_cfg)
        atomic_write_json(CONFIG_FILE, cfg)
    except Exception:
        pass

# ---------------------------- Data ----------------------------

@dataclass
class Item:
    kind: str   # "file" or "folder"
    path: str
    def display(self) -> str:
        return f"[{self.kind}] {self.path}"

# ---------------------------- Backup Tab ----------------------------

class BackupTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.items: List[Item] = []
        self.worker: Optional[threading.Thread] = None
        self.dest_root: Optional[Path] = None
        self.backup_root: Optional[Path] = None
        self.current_prefix: str = ""
        self.current_stamp: str = ""
        self.cancel_flag = False

        # Destination + machine id + prefix
        top = ttk.LabelFrame(self, text="Backup destination")
        top.pack(fill="x", padx=10, pady=(10,6))
        ttk.Label(top, text="Where Backup is Saved:").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        self.dest_entry = ttk.Entry(top)
        self.dest_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=8)
        ttk.Button(top, text="Change Location", command=self.choose_dest).grid(row=0, column=2, padx=8, pady=8)

        ttk.Label(top, text="Machine ID:").grid(row=1, column=0, sticky="w", padx=8, pady=(0,8))
        default_mid = os.environ.get("COMPUTERNAME", "THIS-PC")
        self.machine_entry = ttk.Entry(top, width=28)
        self.machine_entry.grid(row=1, column=1, sticky="w", padx=8, pady=(0,8))
        self.machine_entry.insert(0, default_mid)

        ttk.Label(top, text="Backup Prefix:").grid(row=2, column=0, sticky="w", padx=8, pady=(0,8))
        self.prefix_entry = ttk.Entry(top, width=28)
        self.prefix_entry.grid(row=2, column=1, sticky="w", padx=8, pady=(0,8))

        top.columnconfigure(1, weight=1)

        # Items
        mid = ttk.LabelFrame(self, text="Select local items to back up")
        mid.pack(fill="both", expand=True, padx=10, pady=6)
        btnrow = ttk.Frame(mid)
        btnrow.pack(fill="x", padx=8, pady=6)
        ttk.Button(btnrow, text="Add Folder…", command=self.add_folder).pack(side="left", padx=4)
        ttk.Button(btnrow, text="Add Files…", command=self.add_files).pack(side="left", padx=4)
        ttk.Button(btnrow, text="Remove Selected", command=self.remove_selected).pack(side="left", padx=16)
        ttk.Button(btnrow, text="Clear", command=self.clear_all).pack(side="left", padx=4)
        self.listbox = tk.Listbox(mid, height=12, selectmode="extended")
        self.listbox.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Actions
        act = ttk.Frame(self)
        act.pack(fill="x", padx=10, pady=4)
        ttk.Button(act, text="Run Backup", command=self.run_backup).pack(side="left", padx=4)
        self.open_btn = ttk.Button(act, text="Open Destination", command=self.open_dest, state="disabled")
        self.open_btn.pack(side="left", padx=8)

        # Right side: progress + cancel
        self.progress = ttk.Progressbar(act, mode="determinate", length=260)
        self.progress.pack(side="right", padx=8)
        ttk.Button(act, text="Cancel", command=lambda: setattr(self, "cancel_flag", True)).pack(side="right", padx=4)

        # Log
        logf = ttk.LabelFrame(self, text="Log")
        logf.pack(fill="both", expand=False, padx=10, pady=(6,10))
        self.log = tk.Text(logf, height=10, wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=8)

        # Load saved config; default dest = PROGRAM_ROOT if not set
        cfg = load_config()
        if "dest" in cfg and cfg["dest"]:
            self.dest_entry.insert(0, cfg["dest"])
        else:
            self.dest_entry.insert(0, str(PROGRAM_ROOT))
        if "machine" in cfg:
            self.machine_entry.delete(0, tk.END)
            self.machine_entry.insert(0, cfg["machine"])
        if "prefix" in cfg:
            self.prefix_entry.insert(0, cfg["prefix"])

        self.append(f"App folder: {PROGRAM_ROOT}")
        self.append("Ready to back up.")

    # ---------- Thread-safe UI helpers ----------
    def _append_ui(self, text: str):
        self.log.insert(tk.END, text.rstrip() + "\n")
        self.log.see(tk.END)

    def append(self, text: str):
        if threading.current_thread() is threading.main_thread():
            self._append_ui(text)
        else:
            self.after(0, self._append_ui, text)

    def _set_busy_ui(self, busy: bool):
        state = "disabled" if busy else "normal"
        for child in self.winfo_children():
            for sub in child.winfo_children():
                if sub is self.log or sub is self.progress:
                    continue
                try:
                    sub.configure(state=state)
                except Exception:
                    pass
        if busy:
            self.open_btn.configure(state="disabled")

    def set_busy(self, busy: bool):
        if threading.current_thread() is threading.main_thread():
            self._set_busy_ui(busy)
        else:
            self.after(0, self._set_busy_ui, busy)

    # ---------- callbacks ----------
    def choose_dest(self):
        d = filedialog.askdirectory(title="Choose backup destination", initialdir=str(PROGRAM_ROOT))
        if d:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, clean_path(d))

    def add_folder(self):
        d = filedialog.askdirectory(title="Select a folder to back up")
        if d:
            p = clean_path(d)
            if not Path(p).exists():
                messagebox.showerror("Folder not found", p)
                return
            self.items.append(Item(kind="folder", path=p))
            self.listbox.insert(tk.END, self.items[-1].display())

    def add_files(self):
        files = filedialog.askopenfilenames(title="Select files to back up")
        for f in files:
            p = clean_path(f)
            if Path(p).exists():
                self.items.append(Item(kind="file", path=p))
                self.listbox.insert(tk.END, self.items[-1].display())

    def remove_selected(self):
        sel = list(self.listbox.curselection())
        for idx in reversed(sel):
            self.listbox.delete(idx)
            del self.items[idx]

    def clear_all(self):
        self.items.clear()
        self.listbox.delete(0, tk.END)

    def _preflight(self, dest_root: Path) -> Optional[str]:
        # prevent backing up into a subfolder of any source
        for it in self.items:
            src = Path(it.path)
            if is_subpath(dest_root, src):
                return f"Destination '{dest_root}' is inside source '{src}'. Choose a different destination."
        # prevent overlapping sources (surprising duplication)
        paths = [Path(it.path).resolve(strict=False) for it in self.items]
        for i, a in enumerate(paths):
            for b in paths[i+1:]:
                if a in b.parents or b in a.parents:
                    return f"Selected sources overlap:\n- {a}\n- {b}\nRemove one to avoid duplication."
        return None

    def run_backup(self):
        dest_base = clean_path(self.dest_entry.get())
        if not dest_base:
            messagebox.showerror("Missing destination", "Please choose a destination folder.")
            return
        if not self.items:
            messagebox.showinfo("Nothing to back up", "Add a folder or file first.")
            return

        self.dest_root = Path(dest_base)
        machine_id = (self.machine_entry.get() or "THIS-PC").strip()
        self.current_prefix = self.prefix_entry.get().strip()
        self.current_stamp = now_stamp()
        folder_name = f"{self.current_prefix}_{self.current_stamp}" if self.current_prefix else self.current_stamp
        self.backup_root = self.dest_root / machine_id / "_backups" / folder_name

        msg = self._preflight(self.backup_root)
        if msg:
            messagebox.showerror("Invalid destination", msg)
            return

        save_config({"dest": dest_base, "machine": machine_id, "prefix": self.current_prefix})
        self.cancel_flag = False
        self.set_busy(True)
        self.append(f"Starting backup to: {self.backup_root}")

        # Pre-compute progress maximum
        total_units = 0
        for it in self.items:
            p = Path(it.path)
            total_units += count_files_for_progress(p)
        total_units = max(total_units, 1)
        self.progress.configure(maximum=total_units, value=0)

        t = threading.Thread(target=self._do_backup_worker, daemon=True)
        t.start()
        self.worker = t

    def open_dest(self):
        if self.backup_root and self.backup_root.exists():
            try:
                os.startfile(self.backup_root)  # type: ignore[attr-defined]
            except Exception:
                messagebox.showinfo("Open", str(self.backup_root))

    def _do_backup_worker(self):
        try:
            assert self.backup_root is not None
            ensure_dir(self.backup_root)

            prefix = self.current_prefix
            stamp = self.current_stamp

            manifest = {
                "machine_id": self.machine_entry.get() or "THIS-PC",
                "backup_root": str(self.backup_root),
                "timestamp": stamp,
                "prefix": prefix,
                "items": []  # each has: kind, src, backup_subdir, name, result, detail
            }

            any_fail = False

            def bump():
                # advance the progress bar safely
                self.after(0, lambda: self.progress.configure(value=self.progress["value"] + 1))

            def is_canceled() -> bool:
                return self.cancel_flag

            for it in self.items:
                if is_canceled():
                    self.append("Backup canceled by user.")
                    any_fail = True
                    break
                src = Path(it.path)
                token = sanitize_name(src.name if it.kind == "folder" else src.stem)
                item_dir = self.backup_root / token
                ok, detail = backup_item_to_subdir(src, item_dir, bump=bump, cancel_flag=is_canceled)
                self.append(f"[{token}] {'OK' if ok else 'FAILED'} — {detail}")
                manifest["items"].append({
                    "kind": it.kind,
                    "src": str(src),
                    "name": src.name,
                    "backup_subdir": token,
                    "result": "ok" if ok else "failed",
                    "detail": detail
                })
                if not ok:
                    any_fail = True
                if is_canceled():
                    self.append("Backup canceled by user.")
                    any_fail = True
                    break

            # Write manifest in two places:
            # 1) PROGRAM_ROOT (next to the EXE) for the GUI restore tab
            # 2) Inside the backup folder itself (for headless/auto-restore tools)
            manifest_name = f"backup_manifest_{prefix+'_' if prefix else ''}{stamp}.json"
            manifest_primary = MANIFEST_DIR / manifest_name
            manifest_in_backup = self.backup_root / manifest_name

            try:
                atomic_write_json(manifest_primary, manifest)
                self.append(f"Wrote manifest at {manifest_primary}")
                # Immediately refresh Restore tab list (on UI thread)
                try:
                    self.after(0, self.app.restore_tab.rescan_if_changed)
                except Exception:
                    pass
            except Exception as e:
                self.append(f"Failed writing manifest beside EXE: {e}")
                any_fail = True

            try:
                atomic_write_json(manifest_in_backup, manifest)
                self.append(f"Wrote manifest copy at {manifest_in_backup}")
            except Exception as e:
                self.append(f"Failed writing manifest copy in backup folder: {e}")
                any_fail = True

            self.append("Backup finished " + ("with ISSUES." if any_fail else "OK."))
            self.after(0, lambda: self.open_btn.configure(state="normal"))
        finally:
            self.set_busy(False)
            self.after(0, lambda: self.progress.configure(value=0))
            self.cancel_flag = False

# ---------------------------- Restore Tab ----------------------------

class RestoreTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        cfg = load_config()
        start_dir = Path(cfg.get("restore_dir", str(MANIFEST_DIR)))
        self.current_scan_dir: Path = start_dir if start_dir.exists() else MANIFEST_DIR

        self._manifest_snapshot: List[Tuple[str, float]] = []  # (name, mtime)
        self._auto_refresh_ms: int = 3000
        self._refresh_job: Optional[str] = None
        self.selected_manifest: Optional[dict] = None
        self._rows: List[dict] = []  # {path, prefix, date_epoch, date_str}
        self._iid_to_path: dict[str, Path] = {}
        self._sort_col: str = "date"   # 'prefix' or 'date'
        self._sort_desc: bool = True   # default newest first

        top = ttk.Frame(self); top.pack(fill="x", padx=10, pady=6)
        ttk.Button(top, text="Change Where Loading Backups From", command=self.choose_dest).pack(side="left", padx=4)
        self.dest_label = ttk.Label(top, text=str(self.current_scan_dir)); self.dest_label.pack(side="left", padx=4)

        # Treeview with Prefix + Date columns
        cols = ("prefix", "date")
        treef = ttk.Frame(self); treef.pack(fill="both", expand=True, padx=10, pady=(6,6))
        self.tree = ttk.Treeview(treef, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("prefix", text="Prefix", command=lambda: self.sort_by("prefix"))
        self.tree.heading("date", text="Date", command=lambda: self.sort_by("date"))
        self.tree.column("prefix", width=280, anchor="w")
        self.tree.column("date", width=200, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.load_manifest)

        btnrow = ttk.Frame(self); btnrow.pack(fill="x", padx=10, pady=6)
        self.btn_restore_orig = ttk.Button(btnrow, text="Restore to Original", command=self.restore_original)
        self.btn_restore_orig.pack(side="left", padx=4)
        self.btn_restore_custom = ttk.Button(btnrow, text="Restore to Folder…", command=self.restore_custom)
        self.btn_restore_custom.pack(side="left", padx=4)

        logf = ttk.LabelFrame(self, text="Log")
        logf.pack(fill="both", expand=True, padx=10, pady=6)
        self.log = tk.Text(logf, height=10, wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=8)

        # Initial scan + start auto-refresh
        self._manifest_snapshot = self._snapshot_dir(self.current_scan_dir)
        self.scan_manifests(self.current_scan_dir)
        self.start_auto_refresh()

    # ---------- Logging ----------
    def _append_ui(self, text: str):
        self.log.insert(tk.END, text.rstrip() + "\n")
        self.log.see(tk.END)

    def append(self, text: str):
        if threading.current_thread() is threading.main_thread():
            self._append_ui(text)
        else:
            self.after(0, self._append_ui, text)

    # ---------- Auto-refresh ----------
    def start_auto_refresh(self):
        if self._refresh_job is None:
            self._refresh_job = self.after(self._auto_refresh_ms, self._auto_refresh_tick)

    def stop_auto_refresh(self):
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None

    def _auto_refresh_tick(self):
        try:
            self.rescan_if_changed()
        finally:
            self._refresh_job = self.after(self._auto_refresh_ms, self._auto_refresh_tick)

    # ---------- Scan / Snapshot ----------
    def _snapshot_dir(self, d: Path) -> List[Tuple[str, float]]:
        out: List[Tuple[str, float]] = []
        try:
            for f in d.glob("backup_manifest_*.json"):
                try:
                    out.append((f.name, f.stat().st_mtime))
                except Exception:
                    out.append((f.name, 0.0))
        except Exception:
            pass
        out.sort(key=lambda x: (x[1], x[0]), reverse=True)
        return out

    def rescan_if_changed(self):
        new_snap = self._snapshot_dir(self.current_scan_dir)
        if new_snap == self._manifest_snapshot:
            return
        self._manifest_snapshot = new_snap
        self.scan_manifests(self.current_scan_dir)

    def choose_dest(self):
        d = filedialog.askdirectory(title="Choose manifests folder", initialdir=str(self.current_scan_dir))
        if not d:
            return
        self.current_scan_dir = Path(d)
        self.dest_label.config(text=d)
        save_config({"restore_dir": d})
        self._manifest_snapshot = self._snapshot_dir(self.current_scan_dir)
        self.scan_manifests(self.current_scan_dir)

    def scan_manifests(self, dest: Path):
        # Remember selection (by path) and scroll
        prev_sel_path = None
        sel = self.tree.selection()
        if sel:
            prev_sel_path = self._iid_to_path.get(sel[0])
        y0 = self.tree.yview()[0] if self.tree.get_children() else 0.0

        # Build rows from manifests
        self._rows.clear()
        self._iid_to_path.clear()
        for name, _mtime in self._manifest_snapshot:
            p = dest / name
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                prefix = data.get("prefix", "") or ""
                ts = data.get("timestamp", "") or ""
                epoch, human = ts_to_readable(ts) if ts else (p.stat().st_mtime, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime)))
                self._rows.append({"path": p, "prefix": prefix if prefix else "(none)", "date_epoch": epoch, "date_str": human})
            except Exception:
                # Fallback if file is malformed
                epoch = p.stat().st_mtime if p.exists() else 0.0
                human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else "unknown"
                self._rows.append({"path": p, "prefix": "(unknown)", "date_epoch": epoch, "date_str": human})

        # Sort rows
        self._apply_sort()

        # Rebuild tree
        self.tree.delete(*self.tree.get_children())
        for idx, row in enumerate(self._rows):
            iid = f"row{idx}"
            self._iid_to_path[iid] = row["path"]
            self.tree.insert("", "end", iid=iid, values=(row["prefix"], row["date_str"]))

        # Restore selection and scroll
        if prev_sel_path:
            for iid, path in self._iid_to_path.items():
                if path == prev_sel_path:
                    try:
                        self.tree.selection_set(iid)
                        self.tree.focus(iid)
                        break
                    except Exception:
                        pass
        if self.tree.get_children():
            self.tree.yview_moveto(y0)

    # ---------- Sorting ----------
    def sort_by(self, col: str):
        if col not in ("prefix", "date"):
            return
        if self._sort_col == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = col
            self._sort_desc = (col == "date")  # default: date desc, prefix asc
        self._apply_sort()
        # Rebuild tree with new order
        rows_copy = list(self._rows)
        self.tree.delete(*self.tree.get_children())
        self._iid_to_path.clear()
        for idx, row in enumerate(rows_copy):
            iid = f"row{idx}"
            self._iid_to_path[iid] = row["path"]
            self.tree.insert("", "end", iid=iid, values=(row["prefix"], row["date_str"]))

    def _apply_sort(self):
        if self._sort_col == "prefix":
            self._rows.sort(key=lambda r: (r["prefix"].lower(), r["date_epoch"]), reverse=self._sort_desc)
        else:  # date
            self._rows.sort(key=lambda r: (r["date_epoch"], r["prefix"].lower()), reverse=self._sort_desc)

    # ---------- Manifest load / Restore ----------
    def load_manifest(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        manifest_path = self._iid_to_path.get(sel[0])
        if not manifest_path:
            return
        try:
            self.selected_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.append(f"Loaded manifest: {manifest_path}")
            items = self.selected_manifest.get("items", [])
            for it in items:
                self.append(f"- {it.get('kind')}  {it.get('src')}  [subdir: {it.get('backup_subdir')}]  [{it.get('result')}]")
        except Exception as e:
            self.append(f"Failed reading manifest: {e}")

    def restore_original(self):
        if not self.selected_manifest:
            messagebox.showinfo("No manifest", "Select a backup file first.")
            return
        if not messagebox.askyesno(
            "Confirm",
            "Restore ALL items to their original locations?\n"
            "Existing files/folders will be OVERWRITTEN. This cannot be undone by this app."
        ):
            return
        self._start_restore(custom_base=None)

    def restore_custom(self):
        if not self.selected_manifest:
            messagebox.showinfo("No manifest", "Select a manifest first.")
            return
        base = filedialog.askdirectory(title="Restore into folder")
        if not base:
            return
        self._start_restore(custom_base=Path(base))

    def _start_restore(self, custom_base: Optional[Path]):
        t = threading.Thread(target=self._do_restore_worker, args=(custom_base,), daemon=True)
        t.start()

    def _do_restore_worker(self, custom_base: Optional[Path]):
        try:
            mf = self.selected_manifest
            if not mf:
                self.append("No manifest loaded.")
                return

            backup_root = Path(mf["backup_root"])
            if not backup_root.exists():
                self.append(f"Backup root not found: {backup_root}")
                return

            items = mf.get("items", [])

            for it in items:
                kind = it.get("kind")
                orig_src = Path(it.get("src", ""))  # original path (target for restore-original)
                token = it.get("backup_subdir") or ""
                name = it.get("name") or orig_src.name

                # compatibility for older manifests without backup_subdir
                if not token:
                    guess = sanitize_name(orig_src.name)
                    token = guess if (backup_root / guess).exists() else ""

                item_data_dir = backup_root / token if token else backup_root

                if not item_data_dir.exists():
                    self.append(f"[SKIP] Missing backup data dir for item: {item_data_dir}")
                    continue

                if custom_base is None:
                    # Restore to original locations (overwrite-only)
                    if kind == "folder":
                        ensure_dir(orig_src)
                        for child in item_data_dir.iterdir():
                            restore_copy(child, orig_src / child.name, overwrite=True)
                        self.append(f"[RESTORED] folder contents -> {orig_src}")
                    else:
                        candidate = item_data_dir / name
                        if candidate.exists() and candidate.is_file():
                            restore_copy(candidate, orig_src, overwrite=True)
                        else:
                            files = [p for p in item_data_dir.iterdir() if p.is_file()]
                            if files:
                                restore_copy(files[0], orig_src, overwrite=True)
                            else:
                                self.append(f"[SKIP] No file found to restore for {orig_src}")
                                continue
                        self.append(f"[RESTORED] file -> {orig_src}")
                else:
                    # Restore to custom folder (overwrite-only)
                    if kind == "folder":
                        target_dir = custom_base / name
                        ensure_dir(target_dir)
                        for child in item_data_dir.iterdir():
                            restore_copy(child, target_dir / child.name, overwrite=True)
                        self.append(f"[RESTORED] folder contents -> {target_dir}")
                    else:
                        candidate = item_data_dir / name
                        dest_file = custom_base / name
                        if candidate.exists() and candidate.is_file():
                            restore_copy(candidate, dest_file, overwrite=True)
                        else:
                            files = [p for p in item_data_dir.iterdir() if p.is_file()]
                            if files:
                                restore_copy(files[0], dest_file, overwrite=True)
                            else:
                                self.append(f"[SKIP] No file found to restore for {name}")
                                continue
                        self.append(f"[RESTORED] file -> {dest_file}")

            self.append("Restore completed.")
        except Exception as e:
            self.append(f"Restore failed: {e}")

# ---------------------------- Main ----------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Backup & Restore (Portable, overwrite-only)")
        self.geometry("980x680")
        try:
            import ctypes  # type: ignore
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # improve scaling on Windows
            ttk.Style().theme_use("vista")
        except Exception:
            pass

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        self.backup_tab = BackupTab(nb, self); nb.add(self.backup_tab, text="Backup")
        self.restore_tab = RestoreTab(nb); nb.add(self.restore_tab, text="Restore")
        nb.select(1)  # Default to Restore tab

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
