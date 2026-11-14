"""clipguard: the clipboard door. Any image copied to the clipboard (a Win+Shift+S snip, "copy image" anywhere) is
checked with the same redaction engine as altshot shots. If it shows a secret, the clipboard image is replaced with
the blacked-out version at once, and a matching just-saved screenshot file is overwritten too.

Rules:
- Only image-only clipboards are checked. If text or files are on the clipboard too (a copy from Word, Excel, a
  browser selection, Explorer), nothing is touched: text and file content is never changed.
- A clean image is left exactly as it was: nothing is written.
- Fail closed: if the check errors or times out, the image is replaced with a black "withheld" card, never left
  pasteable unchecked.
- Never loops: every write of ours carries a private marker format and its sequence number is remembered; a
  clipboard carrying a marker is never checked.
- If something newer lands on the clipboard while an image is being checked, the newer content is left alone.

Windows only (user32 / kernel32 through ctypes). The listener is a message-only window that receives
WM_CLIPBOARDUPDATE; the work runs on a worker thread so the message loop never stalls.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import io
import os
import struct
import threading
import time

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

CF_TEXT, CF_DIB, CF_OEMTEXT, CF_UNICODETEXT, CF_HDROP, CF_DIBV5 = 1, 8, 7, 13, 15, 17
TEXT_OR_FILES = {CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT, CF_HDROP}
WM_CLIPBOARDUPDATE = 0x031D
HWND_MESSAGE = wt.HWND(-3)
GMEM_MOVEABLE = 0x0002

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

user32.OpenClipboard.argtypes = [wt.HWND]
user32.OpenClipboard.restype = wt.BOOL
user32.CloseClipboard.restype = wt.BOOL
user32.EmptyClipboard.restype = wt.BOOL
user32.EnumClipboardFormats.argtypes = [wt.UINT]
user32.EnumClipboardFormats.restype = wt.UINT
user32.GetClipboardData.argtypes = [wt.UINT]
user32.GetClipboardData.restype = wt.HANDLE
user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
user32.SetClipboardData.restype = wt.HANDLE
user32.IsClipboardFormatAvailable.argtypes = [wt.UINT]
user32.RegisterClipboardFormatW.argtypes = [wt.LPCWSTR]
user32.RegisterClipboardFormatW.restype = wt.UINT
user32.GetClipboardSequenceNumber.restype = wt.DWORD
user32.AddClipboardFormatListener.argtypes = [wt.HWND]
user32.RemoveClipboardFormatListener.argtypes = [wt.HWND]
user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]
user32.CreateWindowExW.restype = wt.HWND
kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = wt.HGLOBAL
kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
kernel32.GlobalSize.argtypes = [wt.HGLOBAL]
kernel32.GlobalSize.restype = ctypes.c_size_t
kernel32.GlobalFree.argtypes = [wt.HGLOBAL]
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.GetModuleHandleW.restype = wt.HMODULE


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wt.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR),
                ("lpszClassName", wt.LPCWSTR)]


user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.RegisterClassW.restype = wt.ATOM

CF_PNG = user32.RegisterClipboardFormatW("PNG")
MARK_OWN = user32.RegisterClipboardFormatW("AltshotOwnWrite")      # every write of ours
MARK_SKIP = user32.RegisterClipboardFormatW("AltshotSkipCheck")    # tests and clipboard restores
CF_NO_HISTORY = user32.RegisterClipboardFormatW("CanIncludeInClipboardHistory")
CF_NO_CLOUD = user32.RegisterClipboardFormatW("CanUploadToCloudClipboard")


class ClipboardBusy(RuntimeError):
    pass


# ── raw clipboard access ─────────────────────────────────────────────────────────────────────────────────────────
class opened:
    """with opened(hwnd): ... — OpenClipboard with retries (the app that just copied may still hold it)."""

    def __init__(self, hwnd, tries: int = 40):
        self.hwnd, self.tries = hwnd, tries

    def __enter__(self):
        for _ in range(self.tries):
            if user32.OpenClipboard(self.hwnd):
                return self
            time.sleep(0.025)
        raise ClipboardBusy("the clipboard stayed locked by another app")

    def __exit__(self, *exc):
        user32.CloseClipboard()


def formats() -> list[int]:
    """The formats on the clipboard. Call with the clipboard open."""
    out, f = [], 0
    while True:
        f = user32.EnumClipboardFormats(f)
        if not f:
            return out
        out.append(f)


def get_bytes(fmt: int) -> bytes | None:
    """One HGLOBAL format's bytes. Call with the clipboard open."""
    h = user32.GetClipboardData(fmt)
    if not h:
        return None
    p = kernel32.GlobalLock(h)
    if not p:
        return None
    try:
        return ctypes.string_at(p, kernel32.GlobalSize(h))
    finally:
        kernel32.GlobalUnlock(h)


def put_bytes(fmt: int, data: bytes) -> None:
    """Hand one format to the clipboard (it then owns the memory). Call with the clipboard open and emptied."""
    h = kernel32.GlobalAlloc(GMEM_MOVEABLE, max(1, len(data)))
    if not h:
        raise MemoryError("GlobalAlloc failed")
    p = kernel32.GlobalLock(h)
    ctypes.memmove(p, data, len(data))
    kernel32.GlobalUnlock(h)
    if not user32.SetClipboardData(fmt, h):
        kernel32.GlobalFree(h)
        raise OSError(f"SetClipboardData({fmt}) failed: {ctypes.get_last_error()}")


def dib_to_image(dib: bytes):
    """A CF_DIB / CF_DIBV5 block → PIL image (a BMP file header is put in front and Pillow reads it)."""
    from PIL import Image
    size, _w, _h, _planes, bits, compression, _sz, _x, _y, used = struct.unpack_from("<IiiHHIIiiI", dib, 0)
    masks = 12 if (compression == 3 and size == 40) else 0
    palette = (used or (1 << bits if bits <= 8 else 0)) * 4
    offset = 14 + size + masks + palette
    return Image.open(io.BytesIO(b"BM" + struct.pack("<IHHI", 14 + len(dib), 0, 0, offset) + dib))


def image_to_dib(rgb) -> bytes:
    """RGB uint8 array → a 24-bit bottom-up CF_DIB block."""
    import numpy as np
    h, w = rgb.shape[:2]
    stride = (w * 3 + 3) & ~3
    rows = np.zeros((h, stride), np.uint8)
    rows[:, :w * 3] = rgb[::-1, :, ::-1].reshape(h, w * 3)
    return struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, stride * h, 2835, 2835, 0, 0) + rows.tobytes()


def png_bytes(rgb) -> bytes:
    from PIL import Image
    buf = io.BytesIO()
    Image.fromarray(rgb).save(buf, "PNG")
    return buf.getvalue()


def read_image(hwnd, skip: int = MARK_SKIP):
    """Returns (seq, rgb array, why_not). why_not is set when there is nothing for us to check."""
    import numpy as np
    with opened(hwnd):
        seq = user32.GetClipboardSequenceNumber()
        fm = set(formats())
        if MARK_OWN in fm or skip in fm:
            return seq, None, "ours"
        if fm & TEXT_OR_FILES:
            return seq, None, "text or files on the clipboard: never touched"
        if CF_PNG in fm:
            data, kind = get_bytes(CF_PNG), "png"
        elif CF_DIBV5 in fm or CF_DIB in fm:
            data, kind = get_bytes(CF_DIBV5 if CF_DIBV5 in fm else CF_DIB), "dib"
        else:
            return seq, None, "no image"
    if not data:
        raise ValueError("the image on the clipboard could not be read")
    from PIL import Image
    img = Image.open(io.BytesIO(data)) if kind == "png" else dib_to_image(data)
    return seq, np.asarray(img.convert("RGB")).copy(), ""


def write_image(hwnd, rgb, only_if_seq: int | None = None, marker: int = MARK_OWN) -> int | None:
    """Put an image on the clipboard (PNG + CF_DIB, marked as ours, kept out of clipboard history and the cloud).
    With only_if_seq, nothing is written if the clipboard changed since that sequence number. Returns the new
    sequence number, or None when it stood down."""
    png, dib = png_bytes(rgb), image_to_dib(rgb)
    with opened(hwnd):
        if only_if_seq is not None and user32.GetClipboardSequenceNumber() != only_if_seq:
            return None
        user32.EmptyClipboard()
        put_bytes(CF_PNG, png)
        put_bytes(CF_DIB, dib)
        put_bytes(marker, b"1")
        put_bytes(CF_NO_HISTORY, struct.pack("<I", 0))
        put_bytes(CF_NO_CLOUD, struct.pack("<I", 0))
    return user32.GetClipboardSequenceNumber()


# ── the guard ────────────────────────────────────────────────────────────────────────────────────────────────────
class ClipGuard:
    """check(rgb) -> (boxes, secrets, randoms) or raises; apply(rgb, boxes) blacks out in place;
    card() -> RGB array of the withheld card; log(str); cue(kind) with kind 'hidden' or 'withheld'."""

    def __init__(self, check, apply, card, log, cue, screenshots_dir: str | None = None, file_wait_s: float = 8.0,
                 skip_marker: int = MARK_SKIP):
        self.check, self.apply, self.card, self.log, self.cue = check, apply, card, log, cue
        self.screenshots_dir = screenshots_dir
        self.file_wait_s = file_wait_s
        self.hwnd = None
        self.own: set[int] = set()
        self.lock = threading.Lock()
        self._proc = WNDPROC(self._wndproc)  # kept referenced: Windows calls it
        self.last: dict = {}                  # the last result, for tests
        self.skip_marker = skip_marker
        self.events = 0                       # clipboard updates seen (ours included)
        self.checks = 0                       # images actually run through the check
        self.done = 0                         # updates fully handled (for tests)

    def start(self) -> None:
        """Create the hidden listener window. Call on a thread that runs a message loop."""
        inst = kernel32.GetModuleHandleW(None)
        cls = WNDCLASSW()
        cls.lpfnWndProc = self._proc
        cls.hInstance = inst
        cls.lpszClassName = f"altshot-clipguard-{os.getpid()}-{id(self)}"
        if not user32.RegisterClassW(ctypes.byref(cls)):
            raise OSError(f"RegisterClassW failed: {ctypes.get_last_error()}")
        self.hwnd = user32.CreateWindowExW(0, cls.lpszClassName, "altshot clipboard guard", 0, 0, 0, 0, 0,
                                           HWND_MESSAGE, None, inst, None)
        if not self.hwnd or not user32.AddClipboardFormatListener(self.hwnd):
            raise OSError(f"clipboard listener failed: {ctypes.get_last_error()}")

    def stop(self) -> None:
        if self.hwnd:
            user32.RemoveClipboardFormatListener(self.hwnd)
            user32.DestroyWindow(self.hwnd)
            self.hwnd = None

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_CLIPBOARDUPDATE:
            seq = user32.GetClipboardSequenceNumber()
            self.events += 1
            if seq not in self.own:
                threading.Thread(target=self.handle, args=(time.perf_counter(), time.time()), daemon=True).start()
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def handle(self, t0: float, wall0: float, wait_file: bool = False) -> dict:
        """Check what is on the clipboard now; swap it if it shows a secret. Returns what happened. The matching
        screenshot file is fixed on its own thread (it may take seconds to appear); wait_file=True waits for it."""
        try:
            res, fix = self._handle(t0, wall0)
        except Exception as e:  # never die silently
            self.log(f"clipboard guard error: {type(e).__name__}: {e}")
            res, fix = {"action": "error", "why": f"{type(e).__name__}: {e}"}, None
            self.last = res
        finally:
            self.done += 1
        if fix:
            th = threading.Thread(target=self._fix_and_log, args=(*fix, res), daemon=True)
            th.start()
            if wait_file:
                th.join()
        return res

    def _fix_and_log(self, raw, replacement, wall0, res) -> None:
        try:
            res["file"] = self._fix_file(raw, replacement, wall0)
            if res["file"]:
                self.log(f"clipboard image: the saved screenshot {os.path.basename(res['file'])} was overwritten "
                         f"with the {'withheld card' if res['action'] == 'withheld' else 'redacted image'}")
        except Exception as e:
            self.log(f"clipboard guard: could not fix the saved screenshot: {type(e).__name__}: {e}")

    def _handle(self, t0: float, wall0: float):
        with self.lock:
            res = {"action": "none", "why": "", "ms": 0.0, "secrets": 0, "random": 0, "file": ""}
            for attempt in range(4):
                try:
                    seq, rgb, why = read_image(self.hwnd, self.skip_marker)
                    res["read_ms"] = (time.perf_counter() - t0) * 1000
                    break
                except ClipboardBusy:
                    if attempt == 3:
                        res.update(action="error", why="the clipboard stayed locked by another app; not checked")
                        self.log(f"clipboard guard: {res['why']}")
                        self.last = res
                        return res, None
                    time.sleep(0.3)
                except Exception as e:  # an image is there but unreadable: it can't be checked, so it's withheld
                    seq, rgb, why = None, None, f"unreadable image: {type(e).__name__}: {e}"
                    break
            if seq is None:
                res["why"] = why
                self._withhold(user32.GetClipboardSequenceNumber(), res, t0)
                self.last = res
                return res, None
            if seq in self.own or rgb is None:
                res["why"] = why or "ours"
                self.last = res
                return res, None
            try:
                self.checks += 1
                tc = time.perf_counter()
                boxes, secrets, randoms = self.check(rgb)
                res["check_ms"] = (time.perf_counter() - tc) * 1000
            except Exception as e:  # fail closed
                res["why"] = f"{type(e).__name__}: {e}"
                card = self._withhold(seq, res, t0)
                self.last = res
                return res, ((rgb, card, wall0) if card is not None else None)
            if not boxes:
                res.update(action="clean", ms=(time.perf_counter() - t0) * 1000)
                self.last = res
                return res, None
            raw = rgb.copy()
            self.apply(rgb, boxes)
            new = write_image(self.hwnd, rgb, only_if_seq=seq)
            if new is None:
                res.update(action="stood down", why="newer content landed on the clipboard first")
                self.last = res
                return res, None
            self.own.add(new)
            res.update(action="hidden", secrets=secrets, random=randoms, ms=(time.perf_counter() - t0) * 1000)
            self.cue("hidden")
            self.log(f"clipboard image: {secrets} secret(s) + {randoms} random string(s) hidden in {res['ms']:.0f} ms")
            self.last = res
            return res, (raw, rgb, wall0)

    def _withhold(self, seq, res, t0):
        """Replace the clipboard image with the withheld card. Returns the card, or None if it stood down."""
        card = self.card()
        new = write_image(self.hwnd, card, only_if_seq=seq)
        if new is None:
            res.update(action="stood down", why=res["why"] + "; newer content landed first")
            return None
        self.own.add(new)
        res.update(action="withheld", ms=(time.perf_counter() - t0) * 1000)
        self.cue("withheld")
        self.log(f"clipboard image WITHHELD ({res['why']}): replaced with the withheld card in {res['ms']:.0f} ms")
        return card

    def _fix_file(self, raw, replacement, wall0: float) -> str:
        """The screenshot tool may also have saved the raw image as a file: find the file whose pixels are exactly
        the raw image (saved within a few seconds of the copy) and overwrite it in place."""
        folder = self.screenshots_dir
        if not folder or not os.path.isdir(folder):
            return ""
        import numpy as np
        from PIL import Image
        deadline = time.time() + self.file_wait_s
        while True:
            for name in os.listdir(folder):
                if not name.lower().endswith(".png"):
                    continue
                path = os.path.join(folder, name)
                try:
                    if os.path.getmtime(path) < wall0 - 5:
                        continue
                    with Image.open(path) as im:
                        if im.size != (raw.shape[1], raw.shape[0]):
                            continue
                        same = np.array_equal(np.asarray(im.convert("RGB")), raw)
                    if not same:
                        continue
                    data = png_bytes(replacement)
                    with open(path, "r+b") as fh:  # overwrite in place: no second copy is made
                        fh.write(data)
                        fh.truncate()
                    return path
                except (OSError, ValueError, SyntaxError):
                    continue  # still being written, or not an image yet: look again
            if time.time() >= deadline:
                return ""
            time.sleep(0.25)
