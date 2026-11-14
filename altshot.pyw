"""altshot: press LEFT Alt + RIGHT Alt together → a screenshot of the whole screen (every monitor), with any
secrets on it blacked out before it is saved. It also guards the clipboard: an image copied there (a Win+Shift+S
snip, "copy image") that shows a secret is swapped for the blacked-out version.

How it fits together:
  - this watcher (always on, one copy) sees the two Alts through a low-level keyboard hook and captures the screen
    INTO MEMORY
  - before anything touches the disk, the shot is read with Windows' built-in OCR and checked against
    secret_patterns.json (redact.py). Secrets are blacked out in memory; only the safe image is ever written
    (state/shots/, name ends in "-hidden-N" when N things were covered). If the check fails or times out, the real
    pixels are dropped and a black "withheld" card is saved instead: it fails closed, never open
  - the clipboard door (clipguard.py) runs the same check on every image-only clipboard
  - optional hand-off: with a companion that writes state/last.json, the shot is offered to it (see route())

It never swallows the Alt keys; it only taps one unassigned key the instant it fires, so letting go of Alt doesn't
pop open the focused app's menu bar. Needs mss, numpy, Pillow, scipy, and Windows PowerShell 5.1 (built in) for
OCR. Settings: altshot.config.json next to this file (all optional; see altshot.config.example.json)."""
import ctypes
import ctypes.wintypes as wt
import json
import os
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {
    "state_dir": "state",          # relative to this file, or absolute
    "keep_shots": 200,             # older shots are deleted, oldest first
    "redact": True,                # find secrets and black them out before the shot is saved
    "ocr_language": "en-US",
    "ocr_scales": [1, 2],          # OCR passes: as captured, then upscaled 2x (catches small text)
    "ocr_timeout_s": 4.0,          # past this the shot is withheld, never saved unchecked
    "clipboard": True,             # check every image copied to the clipboard too (snips, "copy image")
    "clipboard_timeout_s": 6.0,    # past this a clipboard image is replaced with the withheld card
    "screenshots_dir": "",         # where the snipping tool saves; empty = Windows' own Screenshots folder
    "handoff": True,               # offer each shot to a companion app if one has written state/last.json
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(os.path.join(ROOT, "altshot.config.json"), encoding="utf-8") as fh:
            cfg.update({k: v for k, v in json.load(fh).items() if k in DEFAULTS})
    except FileNotFoundError:
        pass
    except Exception:
        pass  # a broken config falls back to the defaults (which redact)
    return cfg


CFG = load_config()
STATE = CFG["state_dir"] if os.path.isabs(CFG["state_dir"]) else os.path.join(ROOT, CFG["state_dir"])
SHOTS = os.path.join(STATE, "shots")
PENDING = os.path.join(STATE, "pending")
LAST = os.path.join(STATE, "last.json")
LOG = os.path.join(STATE, "altshot.log")
MARK = 0x414C5453           # "ALTS": our own injected key, ignored by the hook

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
WH_KEYBOARD_LL, HC_ACTION = 13, 0
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x100, 0x101, 0x104, 0x105
VK_LMENU, VK_RMENU, VK_UNASSIGNED = 0xA4, 0xA5, 0xE8
LRESULT = ctypes.c_ssize_t


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wt.DWORD), ("scanCode", wt.DWORD), ("flags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("_pad", ctypes.c_byte * 32)]
    _anonymous_ = ("u",)
    _fields_ = [("type", wt.DWORD), ("u", _U)]


HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wt.WPARAM, wt.LPARAM)
user32.SetWindowsHookExW.argtypes = (ctypes.c_int, HOOKPROC, wt.HINSTANCE, wt.DWORD)
user32.SetWindowsHookExW.restype = wt.HHOOK
user32.CallNextHookEx.argtypes = (wt.HHOOK, ctypes.c_int, wt.WPARAM, wt.LPARAM)
user32.CallNextHookEx.restype = LRESULT
user32.SendInput.argtypes = (wt.UINT, ctypes.POINTER(INPUT), ctypes.c_int)


def log(line: str) -> None:
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")
    except Exception:
        pass


def tap_unassigned() -> None:
    """One press of an unassigned key, marked as ours: Windows then treats the Alt as 'used with a key', so its
    release doesn't open the focused app's menu bar."""
    arr = (INPUT * 2)()
    for i, flags in enumerate((0, 2)):  # down, KEYEVENTF_KEYUP
        arr[i].type = 1
        arr[i].ki = KEYBDINPUT(VK_UNASSIGNED, 0, flags, 0, MARK)
    user32.SendInput(2, arr, ctypes.sizeof(INPUT))


def write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


# ── capture → check → save ───────────────────────────────────────────────────────────────────────────────────────
_worker = None
_patterns = None
_shot_lock = threading.Lock()
_checker_lock = threading.Lock()


def checker():
    """The OCR worker and the pattern list, loaded once (lazily, so a broken OCR never stops the watcher)."""
    global _worker, _patterns
    import redact
    with _checker_lock:
        if _patterns is None:
            _patterns = redact.load_patterns()
        if _worker is None:
            _worker = redact.OcrWorker(CFG["ocr_language"])
        _worker.ensure()
        return redact, _worker, _patterns


def grab_screen():
    """The whole virtual screen (every monitor) as an RGB uint8 array, in memory only."""
    import mss
    import numpy as np
    with mss.mss() as s:
        g = s.grab(s.monitors[0])
        return np.frombuffer(g.rgb, dtype=np.uint8).reshape(g.height, g.width, 3).copy()


def _new_path(suffix: str = "") -> str:
    os.makedirs(SHOTS, exist_ok=True)
    stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{int(time.time() * 1000) % 1000:03d}"
    return os.path.join(SHOTS, f"shot-{stamp}{suffix}.png")


def _write_png(rgb, path: str) -> None:
    import mss.tools
    h, w = rgb.shape[:2]
    mss.tools.to_png(rgb.tobytes(), (w, h), output=path)


def withheld_card_image(reason: str, what: str = "screenshot", retry: str = "Press both Alts again to retry."):
    """A small black card that says the image was withheld (PIL image)."""
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (900, 120), (0, 0, 0))
    d = ImageDraw.Draw(img)
    d.text((20, 20), f"altshot: {what} WITHHELD (the original was not kept)", fill=(255, 255, 255))
    d.text((20, 50), f"The secret check could not finish: {reason[:110]}", fill=(255, 200, 120))
    d.text((20, 80), retry, fill=(200, 200, 200))
    return img


def _withheld_card(reason: str) -> str:
    """Save the withheld card as the shot. The real pixels are never written."""
    path = _new_path("-withheld")
    withheld_card_image(reason).save(path)
    return path


def screenshots_folder() -> str:
    """Where the snipping tool saves: the config, else Windows' own Screenshots known folder."""
    if CFG["screenshots_dir"]:
        return os.path.expandvars(CFG["screenshots_dir"])
    try:
        import uuid
        guid = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID("b7bede81-df94-4682-a7d8-57a52620b86f").bytes_le)
        out = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) == 0:
            path = out.value
            ctypes.windll.ole32.CoTaskMemFree(out)
            return path or ""
    except Exception:
        pass
    return ""


def start_clipguard():
    """The clipboard door: same engine, same patterns. Runs on the thread that owns the message loop."""
    import clipguard
    import numpy as np

    def check(rgb):
        redact, worker, patterns = checker()
        gray = (rgb[..., 0].astype("uint16") * 77 + rgb[..., 1].astype("uint16") * 150
                + rgb[..., 2].astype("uint16") * 29 >> 8).astype("uint8")
        r = redact.analyze(gray, worker, patterns, tuple(CFG["ocr_scales"]), float(CFG["clipboard_timeout_s"]))
        return r.boxes, r.count, r.random

    def apply(rgb, boxes):
        import redact
        redact.apply_boxes(rgb, boxes)

    def card():
        return np.asarray(withheld_card_image("see the altshot log", "clipboard image",
                                              "Copy or snip it again to retry.")).copy()

    def cue(kind):
        import winsound
        winsound.MessageBeep(0x00000010 if kind == "withheld" else 0x00000040)

    guard = clipguard.ClipGuard(check, apply, card, log, cue, screenshots_folder())
    guard.start()
    return guard


def _prune() -> None:
    try:
        shots = sorted(f for f in os.listdir(SHOTS) if f.endswith(".png"))
    except OSError:
        return
    for old in shots[:-int(CFG["keep_shots"])]:
        try:
            os.remove(os.path.join(SHOTS, old))
        except OSError:
            pass


def take(grab=grab_screen) -> dict:
    """Capture, check, and save one shot. Returns {path, hidden, withheld, patterns, ms}. Nothing unchecked ever
    reaches the disk: the PNG is written only after the check, and only with the secrets already blacked out."""
    t0 = time.perf_counter()
    rgb = grab()
    secrets, randoms, withheld, fired = 0, 0, "", []
    if CFG["redact"]:
        try:
            redact, worker, patterns = checker()
            gray = (rgb[..., 0].astype("uint16") * 77 + rgb[..., 1].astype("uint16") * 150
                    + rgb[..., 2].astype("uint16") * 29 >> 8).astype("uint8")
            r = redact.analyze(gray, worker, patterns, tuple(CFG["ocr_scales"]), float(CFG["ocr_timeout_s"]))
            del gray
            if r.boxes:
                redact.apply_boxes(rgb, r.boxes)
            secrets, randoms, fired = r.count, r.random, r.patterns
        except Exception as e:  # fail closed: the screen is dropped, never saved unchecked
            withheld = f"{type(e).__name__}: {e}"
    hidden = secrets + randoms
    if withheld:
        del rgb
        path = _withheld_card(withheld)
    else:
        path = _new_path(f"-hidden-{hidden}" if hidden else "")
        _write_png(rgb, path)
        del rgb
    _prune()
    return {"path": path, "hidden": hidden, "secrets": secrets, "random": randoms, "withheld": withheld,
            "patterns": fired, "ms": (time.perf_counter() - t0) * 1000}


def note(shot: dict) -> str:
    """The words that ride with the shot to the agent: what was hidden, never what it was."""
    if shot["withheld"]:
        return "screenshot withheld: the secret check failed, nothing from the screen was saved"
    parts = []
    if shot["secrets"]:
        parts.append(f"{shot['secrets']} secret{'s' if shot['secrets'] != 1 else ''}")
    if shot["random"]:
        parts.append(f"{shot['random']} random-looking string{'s' if shot['random'] != 1 else ''}")
    return f"{' + '.join(parts)} hidden under black boxes" if parts else ""


def route(shot: dict) -> str:
    """Optional hand-off. If a companion (such as the Claude Code mod in claude-code-mod/) has written
    state/last.json = {"session": "<id>"}, the shot is offered to that session by writing
    state/pending/<id>.json = {path, at, hidden, secrets, random, withheld, note}. Without a companion this does
    nothing: the shot is already saved and the watcher works on its own. Returns who got it."""
    if not CFG["handoff"]:
        return "nobody (hand-off off)"
    try:
        with open(LAST, encoding="utf-8") as fh:
            sid = str(json.load(fh)["session"])
        if not sid or not sid.replace("-", "").isalnum():
            raise ValueError
    except Exception:
        return "nobody (no companion)"
    write_json(os.path.join(PENDING, f"{sid}.json"),
               {"path": shot["path"], "at": time.time(), "hidden": shot["hidden"], "secrets": shot["secrets"],
                "random": shot["random"], "withheld": shot["withheld"], "note": note(shot)})
    return f"session {sid}"


def shoot() -> None:
    with _shot_lock:
        try:
            tap_unassigned()
            shot = take()
            who = route(shot)
            what = (f"WITHHELD ({shot['withheld']})" if shot["withheld"]
                    else f"{note(shot)} [{', '.join(shot['patterns'])}]" if shot["hidden"] else "clean")
            log(f"shot {os.path.basename(shot['path'])} in {shot['ms']:.0f} ms, {what} -> {who}")
            import winsound
            # a soft 'got it'; the harsher error sound when the shot was withheld
            winsound.MessageBeep(0x00000010 if shot["withheld"] else 0x00000040)
        except Exception as e:
            log(f"shot failed: {type(e).__name__}: {e}")


down: set[int] = set()
fired = False


def hook(n_code, w_param, l_param):
    global fired
    try:
        if n_code == HC_ACTION:
            k = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            if k.dwExtraInfo != MARK and k.vkCode in (VK_LMENU, VK_RMENU):
                if w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
                    down.add(k.vkCode)
                    if not fired and down == {VK_LMENU, VK_RMENU}:
                        fired = True  # once per press: both must be let go before it fires again
                        threading.Thread(target=shoot, daemon=True).start()
                elif w_param in (WM_KEYUP, WM_SYSKEYUP):
                    down.discard(k.vkCode)
                    if not down:
                        fired = False
    except Exception:
        pass
    return user32.CallNextHookEx(None, n_code, w_param, l_param)


def warm() -> None:
    """Load the OCR engine at start so the first shot isn't slowed by it."""
    if not CFG["redact"]:
        return
    try:
        t0 = time.perf_counter()
        checker()
        log(f"secret check ready in {1000 * (time.perf_counter() - t0):.0f} ms")
    except Exception as e:
        log(f"secret check not ready yet ({type(e).__name__}: {e}); shots are withheld until it is")


def main() -> None:
    mutex = kernel32.CreateMutexW(None, False, "Local\\altshot")
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS: one watcher is enough
        return
    import sys
    sys.path.insert(0, ROOT)
    proc = HOOKPROC(hook)
    h = user32.SetWindowsHookExW(WH_KEYBOARD_LL, proc, None, 0)
    if not h:
        log(f"could not install the keyboard hook (error {ctypes.get_last_error()})")
        return
    log(f"watching for Left Alt + Right Alt (pid {os.getpid()}, redact={'on' if CFG['redact'] else 'OFF'})")
    threading.Thread(target=warm, daemon=True).start()
    guard = None
    if CFG["redact"] and CFG["clipboard"]:
        try:
            guard = start_clipguard()
            log(f"watching the clipboard for images (screenshots folder: {guard.screenshots_dir or 'none'})")
        except Exception as e:
            log(f"clipboard guard could not start: {type(e).__name__}: {e}")
    msg = wt.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))
    _ = (mutex, guard)


if __name__ == "__main__":
    main()
