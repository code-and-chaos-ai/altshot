"""altshot redaction tests, on synthetic screens only (fake secrets drawn with Pillow; never the live screen).

Run:  python tests/test_redaction.py          (exit 0 = all green)
Proves: every fake secret is fully covered, the count is right, a clean screen comes out byte-identical, a secret
shot leaves no unredacted file on disk (shots dir and %TEMP%), and a failed check withholds the shot.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import random
import shutil
import string
import sys
import tempfile
import time

import numpy as np
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import redact  # noqa: E402

W, H = 1920, 1080
FONTS = {"mono": "consola.ttf", "ui": "segoeui.ttf"}
THEMES = {"dark": ((30, 30, 30), (212, 212, 212)), "light": ((255, 255, 255), (36, 36, 36)),
          "dark-color": ((30, 30, 30), (206, 145, 120)), "light-color": ((255, 255, 255), (163, 21, 21))}
rng = random.Random(1405)


def r(n, alphabet=string.ascii_letters + string.digits):
    s = "".join(rng.choice(alphabet) for _ in range(n))
    # make sure a random fake has the variety real keys have
    return s[:-3] + rng.choice(string.ascii_uppercase) + rng.choice(string.ascii_lowercase) + rng.choice(string.digits)


# Key prefixes are put together at runtime, so no key-shaped text sits anywhere in the source (secret scanners
# such as GitHub push protection would flag it). Every key these tests draw is fake and random.
GHP, GH_PAT, NPG, AKIA = "gh" + "p_", "github" + "_pat_", "np" + "g_", "AK" + "IA"
SK_ANT, SK_PROJ, XOXB, GLPAT = "sk-" + "ant-api03-", "sk-" + "proj-", "xo" + "xb-", "gl" + "pat-"
SK_LIVE, RK_LIVE, EYJ = "sk" + "_live_", "rk" + "_live_", "ey" + "J"
PK_BEGIN, PK_END = "-----BEGIN OPENSSH " + "PRIVATE KEY-----", "-----END OPENSSH " + "PRIVATE KEY-----"


def secrets():
    """(prefix, secret, suffix): only `secret` must be covered. All fake, fresh each run."""
    b64 = string.ascii_letters + string.digits + "+/"
    return [
        ("DATABASE_URL=", f"postgresql://app_user:{r(16)}", "@ep-quiet-sun-123.eu-central-1.aws.neon.tech/app"),
        ("export DB=", f"mysql://root:{r(14)}", "@db.internal:3306/shop"),
        ("MONGO_URI=", f"mongodb+srv://admin:{r(18)}", "@cluster0.ab12c.mongodb.net/"),
        ("cache: ", f"redis://default:{r(20)}", "@redis-12345.c1.cloud.redislabs.com:12345"),
        ("ANTHROPIC_API_KEY=", SK_ANT + r(40, string.ascii_letters + string.digits + "-_"), ""),
        ('OPENAI_API_KEY="', SK_PROJ + r(48), '"'),
        ("token: ", GHP + r(36), ""),
        ("GH_TOKEN=", GH_PAT + r(22) + "_" + r(40), ""),
        ("PGPASSWORD=", NPG + r(12), ""),
        ("aws_access_key_id = ", AKIA + r(16, string.ascii_uppercase + string.digits), ""),
        ("SLACK_BOT_TOKEN=", XOXB + r(11, string.digits) + "-" + r(12, string.digits) + "-" + r(24), ""),
        ("gitlab: ", GLPAT + r(20), ""),
        ("stripe ", SK_LIVE + r(24), " (live)"),
        ("restricted ", RK_LIVE + r(24), ""),
        ("jwt ", EYJ + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + EYJ + r(30) + "." + r(43), ""),
        ("Authorization: Bearer ", r(32), ""),
        ("CLOUDFLARE_API_TOKEN = ", r(40), ""),
        ('"client_secret": "', r(32), '",'),
        ("password: ", "Hunter" + r(6) + "!x", ""),
    ]


PRIVATE_KEY = [PK_BEGIN] + \
    ["".join(rng.choice(string.ascii_letters + string.digits + "+/") for _ in range(64)) for _ in range(4)] + \
    [PK_END]

FILLER = [
    "The build finished in 42 seconds and all 318 tests passed on the main branch.",
    "commit 3f9a2c7  Merge pull request #212 from feature/login (short hash)",
    "Request id 6f1c2e4a-9b3d-4e7a-8c5f-2a1b3c4d5e6f took 128 ms (cache hit)",
    "Forgot your password? We'll email you a reset link. The token expires in 24 hours.",
    "Connect with postgresql://localhost:5432/app_dev for local work (no password needed).",
    "Visit https://example.com/docs/getting-started#install for the quickstart guide.",
    "token_count: 1234567  max_tokens: 4096  temperature: 0.7  model: some-model-name",
    "function getToken(user) { return session.refreshTokenFor(user.id); }",
    "Keyboard shortcuts: press Ctrl+K to search, Ctrl+Shift+P for the command palette.",
    "The secret ingredient is cinnamon. Bake at 180 C for 25 minutes until golden.",
    "api_key = os.environ['API_KEY']   # read from the environment, never hard-coded",
    "Saved C:/Projects/app/src/components/settings/profile-page.tsx at 14:02",
]


def font(kind, size):
    return ImageFont.truetype(FONTS[kind], size)


def render(theme, kind, size, with_secrets=True, with_key=False):
    """A full 1080p 'screen': filler text, and secrets on their own rows. Returns (rgb, [must-cover boxes])."""
    bg, fg = THEMES[theme]
    img = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(img)
    f = font(kind, size)
    step = int(size * 1.6)
    y = 20
    want = []
    items = secrets() if with_secrets else []
    i = 0
    while y < H - step:
        x = 24 + (i % 3) * 37
        if items and i % 2 == 1:
            pre, sec, post = items.pop(0)
            d.text((x, y), pre + sec + post, font=f, fill=fg)
            x0 = x + d.textlength(pre, font=f)
            x1 = x + d.textlength(pre + sec, font=f)
            top, bottom = d.textbbox((x, y), pre + sec + post, font=f)[1::2]
            want.append((int(x0), int(top), int(np.ceil(x1)), int(bottom)))
        else:
            d.text((x, y), FILLER[i % len(FILLER)], font=f, fill=fg)
        y += step
        i += 1
    if with_key:
        y = 40
        x = 1100
        tops = []
        for line in PRIVATE_KEY:
            d.text((x, y), line, font=f, fill=fg)
            tops.append(d.textbbox((x, y), line, font=f))
            y += step
        # the body (between BEGIN and END) must be covered
        body = tops[1:-1]
        want.append((min(b[0] for b in body), min(b[1] for b in body), max(b[2] for b in body),
                     max(b[3] for b in body)))
    return np.asarray(img).copy(), want


def gray_of(rgb):
    return (rgb[..., 0].astype("uint16") * 77 + rgb[..., 1].astype("uint16") * 150
            + rgb[..., 2].astype("uint16") * 29 >> 8).astype("uint8")


def coverage(want, boxes, shape=(H, W)):
    mask = np.zeros(shape, bool)
    for x0, y0, x1, y1 in boxes:
        mask[y0:y1, x0:x1] = True
    return [float(mask[y0:y1, x0:x1].mean()) for x0, y0, x1, y1 in want]


def _touch(a, b):
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def load_altshot():
    spec = importlib.util.spec_from_loader("altshot_mod", importlib.machinery.SourceFileLoader(
        "altshot_mod", os.path.join(ROOT, "altshot.pyw")))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    failures = []
    # 0. the pattern file is sane: every regex compiles, no control characters (a lost backslash turns \b into one)
    import json
    with open(redact.PATTERNS_FILE, encoding="utf-8") as fh:
        spec = json.load(fh)
    for p in spec["patterns"]:
        for k in ("regex", "end_regex"):
            if k in p and any(ord(c) < 32 for c in p[k]):
                failures.append(f"pattern {p['id']}: control character in {k}")
    pats = redact.load_patterns()
    print(f"patterns: {len(pats)} loaded, {'clean' if not failures else 'BROKEN'}")
    worker = redact.OcrWorker()
    t = time.perf_counter()
    worker.ensure()
    print(f"OCR worker ready in {(time.perf_counter() - t) * 1000:.0f} ms")
    timings = []
    extras_total = []

    # 1. every fake secret covered, the count right: 2 font kinds x 2 sizes x 4 themes (+ a private key block)
    for kind in ("mono", "ui"):
        for size in (12, 15):
            for theme in THEMES:
                rgb, want = render(theme, kind, size, with_key=(theme == "dark"))
                t = time.perf_counter()
                res = redact.analyze(gray_of(rgb), worker, pats)
                ms = (time.perf_counter() - t) * 1000
                timings.append(ms)
                cov = coverage(want, res.boxes)
                missed = [i for i, c in enumerate(cov) if c < 1.0]
                per = [[g for g in res.groups if _touch(g[0], b)] for b in want]
                double = [i for i, g in enumerate(per) if len(g) > 1]
                extra = [g for g in res.groups if not any(_touch(g[0], b) for b in want)]
                ok = not missed and not double and res.count + res.random - len(extra) == len(want)
                tag = f"{kind:4} {size}px {theme:11}"
                by_pattern = sum(1 for g in per if g and any(k in ("token", "block") for k in g[0][1]))
                print(f"{tag} secrets {len(want):2}: covered {len(want) - len(missed):2}, by a pattern {by_pattern:2}, "
                      f"by the random net {len(want) - by_pattern:2}, counted twice {len(double)}, "
                      f"extra items {len(extra)}  {ms:4.0f} ms {'OK' if ok else 'FAIL'}")
                extras_total.append(len(extra))
                for i in missed:
                    failures.append(f"{tag}: secret #{i} covered {cov[i]:.1%}")
                for i in double:
                    failures.append(f"{tag}: secret #{i} counted {len(per[i])} times")
                if res.count + res.random - len(extra) != len(want):
                    failures.append(f"{tag}: counted {res.count}+{res.random} (minus {len(extra)} extra) "
                                    f"for {len(want)} secrets")

    # 2. clean screens (ordinary text, small and normal): no rule may fire. The one thing allowed is the pixel net
    #    hiding a long string OCR could not read at all (by design: unreadable is treated as unsafe); it is counted
    #    and reported as over-hiding, never silently passed.
    over_hidden = []
    clean_checked = 0
    for kind, theme, size in [(k, th, sz) for k in ("mono", "ui") for th in THEMES for sz in (12, 15)]:
        clean_checked += 1
        rgb, _ = render(theme, kind, size, with_secrets=False)
        before = rgb.copy()
        res = redact.analyze(gray_of(rgb), worker, pats)
        redact.apply_boxes(rgb, res.boxes)
        same = np.array_equal(before, rgb)
        fired = [g for g in res.groups if set(g[1]) - {"unread"}]
        unread_only = [g for g in res.groups if set(g[1]) == {"unread"}]
        over_hidden += unread_only
        verdict = "OK" if not fired and (same or unread_only) else "FAIL"
        print(f"clean {kind} {size}px {theme:11}: rules fired {len(fired)}, unreadable strings hidden "
              f"{len(unread_only)}, untouched {same} {verdict}")
        if verdict == "FAIL":
            failures.append(f"clean {kind} {size}px {theme}: rule(s) fired on clean text "
                            f"[{', '.join(res.patterns)}] at {[g[0] for g in fired]}")

    # 2b. screens bigger than the OCR engine takes (10000 px): every pass still covers all of it, in tiles.
    #     Three monitors (the 2x pass needs tiles) and an extreme 10400 px desktop (even 1x needs tiles).
    for n_screens, extra in ((3, 0), (5, 800)):
        parts, wants = [], []
        for i in range(n_screens):
            rgb, want = render(list(THEMES)[i % len(THEMES)], ("mono", "ui")[i % 2], 15)
            parts.append(rgb)
            wants += [(x0 + i * W, y0, x1 + i * W, y1) for x0, y0, x1, y1 in want]
        if extra:  # a strip on the far right edge, with one secret written right up to it
            strip = Image.new("RGB", (extra, H), (30, 30, 30))
            d = ImageDraw.Draw(strip)
            f = font("mono", 15)
            sec = GHP + r(36)
            d.text((20, 500), sec, font=f, fill=(212, 212, 212))
            top, bottom = d.textbbox((20, 500), sec, font=f)[1::2]
            wants.append((n_screens * W + 20, top, n_screens * W + 20 + int(np.ceil(d.textlength(sec, font=f))), bottom))
            parts.append(np.asarray(strip))
        big = np.ascontiguousarray(np.concatenate(parts, axis=1))
        t = time.perf_counter()
        res = redact.analyze(gray_of(big), worker, pats, timeout=15.0)
        ms = (time.perf_counter() - t) * 1000
        cov = coverage(wants, res.boxes, big.shape[:2])
        missed = [i for i, c in enumerate(cov) if c < 1.0]
        print(f"wide {big.shape[1]}x{big.shape[0]}: secrets {len(wants)}, covered {len(wants) - len(missed)}, "
              f"{ms:.0f} ms {'OK' if not missed else 'FAIL'}")
        for i in missed:
            failures.append(f"wide {big.shape[1]}px: secret #{i} at x={wants[i][0]} covered {cov[i]:.1%}")

    # 2c. secrets laid right across every tile seam (every inner tile edge at 1x and 2x), most of each in the first
    #     tile, so the first tile reads only a cut-off piece and the whole word lives in the next one
    SW = 10400
    seam = Image.new("RGB", (SW, H), (30, 30, 30))
    d = ImageDraw.Draw(seam)
    f = font("mono", 15)
    g0 = np.zeros((H, SW), np.uint8)
    edges = sorted({e for z in (1, 2) for _x, _y, _t, _c, inner in redact.tiles(g0, z)
                    for e in (inner[0], inner[2]) if e is not None})
    seam_want = []
    for k, e in enumerate(edges):
        for j, maker in enumerate((lambda: GHP + r(36), lambda: SK_ANT + r(40),
                                   lambda: AKIA + r(16, string.ascii_uppercase + string.digits))):
            sec = maker()
            width = d.textlength(sec, font=f)
            x = int(e - 0.7 * width)
            y = 60 + (k * 3 + j) * 48
            d.text((x - d.textlength("token: ", font=f), y), "token: " + sec, font=f, fill=(212, 212, 212))
            top, bottom = d.textbbox((x, y), sec, font=f)[1::2]
            seam_want.append((x, top, x + int(np.ceil(width)), bottom))
    big = np.asarray(seam).copy()
    res = redact.analyze(gray_of(big), worker, pats, timeout=15.0)
    cov = coverage(seam_want, res.boxes, big.shape[:2])
    missed = [i for i, c in enumerate(cov) if c < 1.0]
    print(f"tile seams at x={edges}: secrets {len(seam_want)}, covered {len(seam_want) - len(missed)}, "
          f"{'OK' if not missed else 'FAIL'}")
    for i in missed:
        failures.append(f"tile seam: secret #{i} at x={seam_want[i][0]} covered {cov[i]:.1%}")

    # 2d. the 2x pass alone (so the 1x pass can't rescue anything): a token WIDER than the tile overlap laid across
    #     the overlap (no tile holds it whole), and a private-key block whose BEGIN header is cut by a seam
    g2 = np.zeros((H, SW), np.uint8)
    t2 = list(redact.tiles(g2, 2))
    a_end, b_start = t2[0][0] + t2[0][2].shape[1], t2[1][0]          # tile 0 ends, tile 1 starts (overlap)
    canvas = Image.new("RGB", (SW, H), (30, 30, 30))
    d = ImageDraw.Draw(canvas)
    f = font("mono", 15)
    wide_tok = EYJ + r(80) + "." + EYJ + r(80) + "." + r(43)   # ~1700 px: wider than the 1200 px overlap
    wt = d.textlength(wide_tok, font=f)
    x = int((a_end + b_start) / 2 - wt / 2)
    d.text((x, 200), wide_tok, font=f, fill=(212, 212, 212))
    top, bottom = d.textbbox((x, 200), wide_tok, font=f)[1::2]
    seam2_want = [(x, top, x + int(np.ceil(wt)), bottom)]
    header = PK_BEGIN
    core_cut = t2[0][3][2]                                           # where tile 0's core ends and tile 1's begins
    hx = int(core_cut - d.textlength(header, font=f) / 2)            # header words land in two different tiles
    body = ["".join(rng.choice(string.ascii_letters + string.digits + "+/") for _ in range(64)) for _ in range(4)]
    y = 400
    for line in [header] + body + [PK_END]:
        d.text((hx, y), line, font=f, fill=(212, 212, 212))
        y += 24
    bt = [d.textbbox((hx, 424 + 24 * i), b, font=f) for i, b in enumerate(body)]
    seam2_want.append((min(b[0] for b in bt), min(b[1] for b in bt), max(b[2] for b in bt), max(b[3] for b in bt)))
    big = np.asarray(canvas).copy()
    res = redact.analyze(gray_of(big), worker, pats, scales=(2,), timeout=15.0)
    cov = coverage(seam2_want, res.boxes, big.shape[:2])
    names = ["token wider than the overlap", "private key cut by a seam"]
    for i, c in enumerate(cov):
        print(f"2x only, {names[i]}: covered {c:.0%} {'OK' if c >= 1.0 else 'FAIL'}")
        if c < 1.0:
            failures.append(f"2x only, {names[i]}: covered {c:.1%}")
    if "private_key" not in res.patterns:
        failures.append("2x only: the private key header cut by a seam was not recognised as a key block")

    # 2e. a wrapped secret: its second line is short (no rule fires on it alone) and sits on the same row as other
    #     words, so only the continuation rule run on the raw lines catches it
    canvas = Image.new("RGB", (W, H), (30, 30, 30))
    d = ImageDraw.Draw(canvas)
    f = font("mono", 15)
    head, tail = EYJ + "hbGciOiJIUzI1NiJ9." + EYJ + r(20), r(18)
    d.text((40, 300), "jwt: " + head, font=f, fill=(212, 212, 212))
    d.text((40 + d.textlength("jwt: ", font=f), 324), tail, font=f, fill=(212, 212, 212))
    tx = 40 + d.textlength("jwt: " + tail + "   ", font=f)
    d.text((tx, 324), "ok done here", font=f, fill=(212, 212, 212))
    tl = 40 + int(d.textlength("jwt: ", font=f))
    top, bottom = d.textbbox((tl, 324), tail, font=f)[1::2]
    wrap_want = [(tl, top, tl + int(np.ceil(d.textlength(tail, font=f))), bottom)]
    res = redact.analyze(gray_of(np.asarray(canvas).copy()), worker, pats)
    c = coverage(wrap_want, res.boxes)[0]
    print(f"wrapped secret, second line beside other words: covered {c:.0%} {'OK' if c >= 1.0 else 'FAIL'}")
    if c < 1.0:
        failures.append(f"wrapped secret continuation covered {c:.1%}")

    # 2f. wrapped keys whose second line is NOT mixed-case: hex (sk_ + hex) and lowercase+digits (Slack-style),
    #     and a split pane: other text to the right of the key's first line. The second line alone fires no rule.
    hexd, lowd = "0123456789abcdef", string.ascii_lowercase + string.digits
    cases = [("hex", "key: " + "sk" + "_" + r(40, hexd), r(24, hexd), None),
             ("lowercase+digits", "SLACK_BOT_TOKEN=" + XOXB + r(24, lowd), r(22, lowd), None),
             ("split pane", "jwt: " + EYJ + "hbGciOiJIUzI1NiJ9." + EYJ + r(20), r(18), "| right pane: build passed in 42 s")]
    for name, head_line, tail, right in cases:
        canvas = Image.new("RGB", (W, H), (30, 30, 30))
        d = ImageDraw.Draw(canvas)
        d.text((40, 300), head_line, font=f, fill=(212, 212, 212))
        if right:
            d.text((1000, 300), right, font=f, fill=(212, 212, 212))
            d.text((1000, 324), "| more text in the other pane", font=f, fill=(212, 212, 212))
        d.text((40, 324), tail, font=f, fill=(212, 212, 212))
        top, bottom = d.textbbox((40, 324), tail, font=f)[1::2]
        tw = [(40, top, 40 + int(np.ceil(d.textlength(tail, font=f))), bottom)]
        res = redact.analyze(gray_of(np.asarray(canvas).copy()), worker, pats)
        c = coverage(tw, res.boxes)[0]
        print(f"wrapped secret ({name}): second line covered {c:.0%} {'OK' if c >= 1.0 else 'FAIL'}")
        if c < 1.0:
            failures.append(f"wrapped secret ({name}) second line covered {c:.1%}")

    # 3. a secret shot through the real save path: only the redacted PNG exists, nothing in %TEMP%
    out = os.path.join(HERE, "_out")
    shutil.rmtree(out, ignore_errors=True)
    alt = load_altshot()
    alt.STATE, alt.SHOTS, alt.PENDING = out, os.path.join(out, "shots"), os.path.join(out, "pending")
    alt.LAST, alt.LOG = os.path.join(out, "last.json"), os.path.join(out, "altshot.log")
    alt._worker, alt._patterns = worker, pats
    temp = tempfile.gettempdir()
    start = time.time() - 1
    rgb, want = render("dark", "mono", 15)
    shot = alt.take(grab=lambda: rgb.copy())
    saved = np.asarray(Image.open(shot["path"]).convert("RGB"))
    black = all(not saved[y0:y1, x0:x1].any() for x0, y0, x1, y1 in want)
    files = os.listdir(alt.SHOTS)
    new_temp = []
    for dp, _dn, fn in os.walk(temp):
        for f in fn:
            p = os.path.join(dp, f)
            try:
                if os.path.getmtime(p) >= start and f.lower().endswith((".png", ".bmp", ".jpg", ".jpeg", ".raw",
                                                                         ".tif", ".tiff", ".gif", ".webp")):
                    new_temp.append(p)
            except OSError:
                pass
    ok3 = (files == [os.path.basename(shot["path"])] and black and shot["hidden"] >= len(want)
           and "-hidden-" in shot["path"] and not new_temp)
    print(f"save path: files {files}, secrets black {black}, hidden {shot['hidden']}, new images in TEMP "
          f"{len(new_temp)}, {shot['ms']:.0f} ms {'OK' if ok3 else 'FAIL'}")
    if not ok3:
        failures.append(f"save path: files={files} black={black} hidden={shot['hidden']} temp={new_temp[:5]}")
    timings_take = [shot["ms"]]

    # 4. a clean shot through the real save path: saved as today, byte-identical pixels, plain name
    shutil.rmtree(alt.SHOTS, ignore_errors=True)
    rgb, _ = render("light", "ui", 15, with_secrets=False)
    shot = alt.take(grab=lambda: rgb.copy())
    saved = np.asarray(Image.open(shot["path"]).convert("RGB"))
    ok4 = np.array_equal(saved, rgb) and shot["hidden"] == 0 and "-hidden-" not in shot["path"] \
        and not shot["withheld"]
    print(f"clean save: identical {np.array_equal(saved, rgb)}, name {os.path.basename(shot['path'])}, "
          f"{shot['ms']:.0f} ms {'OK' if ok4 else 'FAIL'}")
    if not ok4:
        failures.append("clean save path changed the image or its name")
    timings_take.append(shot["ms"])

    # 5. fail closed: OCR breaks or times out -> withheld card, the real pixels never written
    class Broken:
        def ensure(self):
            pass

        def recognize(self, *_a, **_k):
            raise redact.OcrError("OCR worker exited")

    for label, setup in (("OCR error", lambda: setattr(alt, "_worker", Broken())),
                         ("OCR timeout", lambda: (setattr(alt, "_worker", worker),
                                                  alt.CFG.__setitem__("ocr_timeout_s", 0.001)))):
        shutil.rmtree(alt.SHOTS, ignore_errors=True)
        setup()
        rgb, want = render("dark", "mono", 15)
        shot = alt.take(grab=lambda: rgb.copy())
        files = os.listdir(alt.SHOTS)
        card = np.asarray(Image.open(shot["path"]).convert("RGB"))
        ok5 = bool(shot["withheld"]) and files == [os.path.basename(shot["path"])] and "-withheld" in shot["path"] \
            and card.shape[:2] != rgb.shape[:2]
        print(f"fail closed ({label}): withheld '{shot['withheld'][:60]}', files {files} {'OK' if ok5 else 'FAIL'}")
        if not ok5:
            failures.append(f"fail closed ({label})")
    alt.CFG["ocr_timeout_s"] = 4.0
    alt._worker = worker
    # the worker recovers after a timeout kill: the next shot works again
    shutil.rmtree(alt.SHOTS, ignore_errors=True)
    rgb, want = render("dark", "mono", 15)
    shot = alt.take(grab=lambda: rgb.copy())
    ok6 = not shot["withheld"] and shot["hidden"] >= len(want)
    print(f"recovery after timeout: hidden {shot['hidden']}, {shot['ms']:.0f} ms (includes a worker restart) "
          f"{'OK' if ok6 else 'FAIL'}")
    if not ok6:
        failures.append(f"no recovery after timeout: {shot}")

    shutil.rmtree(out, ignore_errors=True)
    worker.close()
    print(f"\nanalyze() over {len(timings)} screens: median {sorted(timings)[len(timings) // 2]:.0f} ms, "
          f"max {max(timings):.0f} ms; whole take(): {', '.join(f'{t:.0f}' for t in timings_take)} ms; "
          f"extra non-secret items hidden on secret screens: {sum(extras_total)} over {len(extras_total)} screens; "
          f"clean screens: {clean_checked}, unreadable strings hidden on them: {len(over_hidden)}")
    if failures:
        print(f"\n{len(failures)} FAILURE(S):")
        for f in failures:
            print("  -", f)
        return 1
    print("\nALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
