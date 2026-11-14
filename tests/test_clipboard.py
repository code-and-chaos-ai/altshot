"""Clipboard door tests, with synthetic images only.

The clipboard belongs to the person at the machine: this test saves everything on it first and puts it back at the
end (also on failure), then checks the restore byte for byte and says so. Images the test puts on the clipboard
carry the marker the live watcher skips, so a running altshot never touches them; the test runs its own guard.

Run:  python tests/test_clipboard.py          (exit 0 = all green)
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import io
import os
import shutil
import sys
import threading
import time

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import clipguard as cg  # noqa: E402
import redact  # noqa: E402
import test_redaction as T  # noqa: E402

# a fake connection string, assembled at runtime (no key-shaped text in the source)
FAKE_DB_LINE = "DATABASE_URL=" + "postgres" + "ql://app:" + T.NPG + "FakeFake123" + "@host/db"

user32 = cg.user32
TEST_NEVER = user32.RegisterClipboardFormatW("AltshotTestNeverSet")   # the test guard's skip marker: never set
# formats that are GDI/OLE handles, not memory blocks: Windows re-creates them, or they can't be copied
HANDLE_FORMATS = {2, 3, 9, 14, 0x80, 0x82, 0x83, 0x8E}
SKIP_NAMES = {"DataObject", "Ole Private Data", "Object Descriptor", "Link Source Descriptor"}


def fmt_name(f: int) -> str:
    b = ctypes.create_unicode_buffer(256)
    return b.value if user32.GetClipboardFormatNameW(f, b, 256) else str(f)


def save_clipboard(hwnd) -> list[tuple[int, bytes]]:
    saved = []
    with cg.opened(hwnd):
        for f in cg.formats():
            if f in HANDLE_FORMATS or 0x200 <= f <= 0x3FF or fmt_name(f) in SKIP_NAMES:
                continue
            data = cg.get_bytes(f)
            if data is not None:
                saved.append((f, data))
    return saved


def restore_clipboard(hwnd, saved) -> bool:
    """Put your clipboard back. Retries for up to 15 s: giving up early would leave a test image in your clipboard."""
    end = time.time() + 15
    while True:
        try:
            with cg.opened(hwnd):
                user32.EmptyClipboard()
                for f, data in saved:
                    cg.put_bytes(f, data)
                cg.put_bytes(cg.MARK_SKIP, b"1")  # so a running watcher doesn't treat the restore as a new copy
            return True
        except (cg.ClipboardBusy, OSError):
            if time.time() > end:
                return False
            time.sleep(0.2)


def put_test_image(hwnd, rgb) -> int:
    return cg.write_image(hwnd, rgb, marker=cg.MARK_SKIP)


def put_text(hwnd, text: str, with_image=None) -> None:
    with cg.opened(hwnd):
        user32.EmptyClipboard()
        cg.put_bytes(cg.CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))
        if with_image is not None:
            cg.put_bytes(cg.CF_PNG, cg.png_bytes(with_image))
        cg.put_bytes(cg.MARK_SKIP, b"1")


def read_text(hwnd) -> str | None:
    with cg.opened(hwnd):
        data = cg.get_bytes(cg.CF_UNICODETEXT)
    return data.decode("utf-16-le").split("\0")[0] if data else None


def read_png(hwnd) -> tuple[bytes | None, set]:
    with cg.opened(hwnd):
        return cg.get_bytes(cg.CF_PNG), set(cg.formats())


class GuardThread:
    """A ClipGuard with its own message loop, as the watcher runs it."""

    def __init__(self, check, screenshots_dir=None):
        self.ready = threading.Event()
        self.logs: list[str] = []
        self.cues: list[str] = []
        self.check = check
        self.dir = screenshots_dir
        self.guard: cg.ClipGuard | None = None
        self.tid = 0
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(10)

    def _run(self):
        self.tid = ctypes.windll.kernel32.GetCurrentThreadId()
        card = lambda: np.asarray(Image.new("RGB", (900, 120), (0, 0, 0))).copy()  # noqa: E731
        self.guard = cg.ClipGuard(self.check, redact.apply_boxes, card, self.logs.append, self.cues.append,
                                  self.dir, file_wait_s=6.0, skip_marker=TEST_NEVER)
        self.guard.start()
        self.ready.set()
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        self.guard.stop()

    def wait_result(self, since_done: int, timeout=12.0) -> dict:
        """The result of the next clipboard update the guard finishes handling after `since_done`."""
        end = time.time() + timeout
        while time.time() < end:
            if self.guard.done > since_done:
                return self.guard.last
            time.sleep(0.05)
        return {"action": "TIMED OUT"}

    def quit(self):
        user32.PostThreadMessageW(self.tid, 0x0012, 0, 0)  # WM_QUIT


def main() -> int:
    failures = []
    pats = redact.load_patterns()
    worker = redact.OcrWorker()
    worker.ensure()

    def check(rgb):
        r = redact.analyze(T.gray_of(rgb), worker, pats, timeout=8.0)
        return r.boxes, r.count, r.random

    # the test reads and writes with no owner window: an owner window on this thread (which pumps no messages)
    # would stall the guard's next write ~5 s while Windows waits for it to answer
    me = None
    saved = save_clipboard(me)
    names = ", ".join(sorted({fmt_name(f) for f, _ in saved})) or "(empty)"
    print(f"your clipboard saved first: {len(saved)} format(s) [{names}]")
    try:
        out = os.path.join(HERE, "_out-clip")
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(os.path.join(out, "Screenshots"))
        gt = GuardThread(check, os.path.join(out, "Screenshots"))
        try:
            # 1. a secret image is swapped for the blacked-out one, and the matching saved file is overwritten
            rgb, want = T.render("dark", "mono", 15)
            rgb, want = rgb[:400].copy(), [b for b in want if b[3] <= 400]
            other = np.full((300, 500, 3), 200, np.uint8)
            Image.fromarray(other).save(os.path.join(out, "Screenshots", "unrelated.png"))
            before = gt.guard.checks
            before_done = gt.guard.done
            t_put = time.perf_counter()
            put_test_image(me, rgb)
            time.sleep(0.4)  # the snipping tool saves its file a moment after it copies
            Image.fromarray(rgb).save(os.path.join(out, "Screenshots", "snip.png"))
            res = gt.wait_result(before_done)
            swap_ms = (time.perf_counter() - t_put) * 1000
            png, fm = read_png(me)
            got = np.asarray(Image.open(io.BytesIO(png)).convert("RGB")) if png else None
            black = got is not None and all(not got[y0:y1, x0:x1].any() for x0, y0, x1, y1 in want)
            ok = res.get("action") == "hidden" and black and cg.MARK_OWN in fm
            print(f"1. secret image: {res.get('action')}, {res.get('secrets')} secrets + {res.get('random')} random, "
                  f"all {len(want)} black {black}, copy to swap {swap_ms:.0f} ms (check {res.get('ms', 0):.0f} ms) "
                  f"{'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"secret image not swapped: {res}")
            # the saved file
            end = time.time() + 8
            fixed = False
            while time.time() < end and not fixed:
                f_img = np.asarray(Image.open(os.path.join(out, "Screenshots", "snip.png")).convert("RGB"))
                fixed = all(not f_img[y0:y1, x0:x1].any() for x0, y0, x1, y1 in want)
                time.sleep(0.2)
            unrelated_same = np.array_equal(np.asarray(Image.open(os.path.join(out, "Screenshots", "unrelated.png"))
                                                       .convert("RGB")), other)
            files = sorted(os.listdir(os.path.join(out, "Screenshots")))
            ok = fixed and unrelated_same and files == ["snip.png", "unrelated.png"]
            print(f"   saved snip file overwritten with the redacted image {fixed}, unrelated file untouched "
                  f"{unrelated_same}, no extra copies {files} {'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"saved file: fixed={fixed} unrelated={unrelated_same} files={files}")

            # 2. no loop: our own write is not checked again
            time.sleep(1.5)
            ok = gt.guard.checks == before + 1
            print(f"2. no loop: images checked {gt.guard.checks - before} (one), clipboard events seen "
                  f"{gt.guard.events} {'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"loop: {gt.guard.checks - before} checks")

            # 3. a clean image is left exactly as it was
            clean, _ = T.render("light", "ui", 15, with_secrets=False)
            clean = clean[:400].copy()
            before = gt.guard.checks
            before_done = gt.guard.done
            put_test_image(me, clean)
            sent, _ = read_png(me)
            res = gt.wait_result(before_done)
            now, fm = read_png(me)
            ok = res.get("action") == "clean" and now == sent and cg.MARK_OWN not in fm
            print(f"3. clean image: {res.get('action')}, clipboard bytes unchanged {now == sent} "
                  f"{'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"clean image changed: {res}")

            # 4. text, and text with an image beside it: never touched
            before_events = gt.guard.events
            before = gt.guard.checks
            put_text(me, FAKE_DB_LINE)
            time.sleep(1.5)
            t1 = read_text(me)
            rgb2, _ = T.render("dark", "mono", 15)
            put_text(me, "some words", with_image=rgb2[:300].copy())
            sent, _ = read_png(me)
            time.sleep(2.5)
            t2, (now, fm) = read_text(me), read_png(me)
            ok = (gt.guard.checks == before and t1 == FAKE_DB_LINE
                  and t2 == "some words" and now == sent and cg.MARK_OWN not in fm
                  and gt.guard.events >= before_events + 2)
            print(f"4. text untouched {t1 is not None}, text+image untouched {now == sent}, checks run 0 "
                  f"{'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"text clipboard touched: checks {gt.guard.checks - before}, t1={t1!r} t2={t2!r}")
        finally:
            gt.quit()
            time.sleep(0.3)

        # 5. fail closed: the check breaks -> the withheld card, not the raw image
        def broken(_rgb):
            raise redact.OcrError("OCR worker exited")

        gt2 = GuardThread(broken)
        try:
            rgb, _ = T.render("dark", "mono", 15)
            before_done = gt2.guard.done
            put_test_image(me, rgb[:300].copy())
            res = gt2.wait_result(before_done)
            png, fm = read_png(me)
            got = np.asarray(Image.open(io.BytesIO(png)).convert("RGB")) if png else None
            ok = res.get("action") == "withheld" and got is not None and got.shape[:2] == (120, 900) and \
                not got.any() and "withheld" in gt2.cues
            print(f"5. check fails: {res.get('action')}, clipboard holds the withheld card "
                  f"{got is not None and got.shape[:2] == (120, 900)}, cue {gt2.cues} {'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"fail closed: {res}")
        finally:
            gt2.quit()
            time.sleep(0.3)
    except Exception as e:  # a crash must never skip putting your clipboard back
        import traceback
        traceback.print_exc()
        failures.append(f"test crashed: {type(e).__name__}: {e}")
    finally:
        # your clipboard back, byte for byte
        if not restore_clipboard(me, saved):
            failures.append("your clipboard could NOT be restored (stayed locked)")
        again = save_clipboard(me)
        back = {f: d for f, d in again}
        same = all(back.get(f) == d for f, d in saved)
        print(f"your clipboard restored: {len(saved)} format(s), byte for byte {same}")
        if not same:
            failures.append("your clipboard was NOT restored byte for byte")
    worker.close()
    shutil.rmtree(out, ignore_errors=True)
    if failures:
        print(f"\n{len(failures)} FAILURE(S):")
        for f in failures:
            print("  -", f)
        return 1
    print("\nALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
