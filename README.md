# altshot

**Screenshots that hide your secrets before they're saved. Windows only.**

Press **Left Alt + Right Alt** together and the whole screen (every monitor) is captured. Anything on it that
looks like a secret (an API key, a token, a database password, a private key) is blacked out **in memory**,
and only then is the image saved. The same check guards your clipboard: an image you copy or snip
(Win+Shift+S) that shows a secret is swapped for the blacked-out version.

It uses Windows' built-in text recognition. Nothing is sent anywhere and no cloud service is involved.

> **It reduces leaks; it cannot promise none.** Read [What it can miss](#what-it-can-miss) before you rely on it.

## What it does

- **Both Alts → a screenshot, secrets hidden.** The screen is captured into memory, read, checked, blacked out,
  then written to `state/shots/`. A shot that showed secrets is named `…-hidden-N.png`; a clean shot is saved
  exactly as captured.
- **The clipboard door.** When a new image lands on the clipboard, it gets the same check:
  - a secret on it: the clipboard image is replaced by the blacked-out version (with a soft sound), and the
    Snipping Tool's auto-saved copy in your Screenshots folder (the file whose pixels match exactly) is
    overwritten with the same blacked-out image;
  - a clean image: nothing is written; the clipboard stays exactly as it was;
  - text or files on the clipboard (copies from Word, Excel, a browser selection, Explorer): never touched and
    never checked.
- **It fails closed.** If the check errors or runs past its time limit, the original is not kept: a shot is
  saved as a black "withheld" card, and a clipboard image is replaced by that card (with an error sound). Snip
  or press again to retry.
- **No loops, no history.** altshot's own clipboard writes carry a private marker and are never re-checked,
  and they are kept out of Windows' clipboard history and cloud clipboard.

### What counts as a secret

The list lives in [`secret_patterns.json`](secret_patterns.json): plain regular expressions (usable from Python
or JavaScript), with the checks each one needs. It covers:

- connection strings with a password in them (PostgreSQL, MySQL, MongoDB, Redis and others), and any web
  address with a user and password in it;
- API keys and tokens with a known shape: Anthropic, OpenAI, GitHub, GitLab, Slack, Stripe, AWS access keys,
  Neon, Google, Hugging Face, Telegram bots;
- JSON Web Tokens, `Bearer` tokens and private-key blocks;
- a value right after a label such as `password`, `key`, `token` or `secret`;
- long random-looking strings (upper case, lower case and digits mixed), with no label.

Text recognition drops or garbles long random strings, which is exactly what keys look like. So the pixels are
checked too: any long unbroken string the recognizer could not read gets a second, closer read, and stays
hidden unless it then reads as ordinary text. Expect some over-hiding: hashes, IDs and code that can't be read
cleanly are blacked out as well.

## Install

Requirements:
- Windows 10 or 11, with an English text-recognition language (it comes with English Windows). Windows
  PowerShell 5.1, which is built in, reaches the recognizer; nothing else is installed.
- Python 3.10 or newer.

```
pip install -r requirements.txt
```

Run it:

```
pythonw altshot.pyw
```

It runs in the background with no window: one copy at a time, and a second start exits on its own. What it does
is written to `state/altshot.log`.

**Run at login (optional, and not set up for you).** Put a shortcut in your Startup folder (`Win+R`, type
`shell:startup`) whose target is `pythonw.exe "<full path to>\altshot.pyw"`, starting in the altshot folder.

## Configuration

Copy [`altshot.config.example.json`](altshot.config.example.json) to `altshot.config.json` next to
`altshot.pyw` and change what you need. Every key is optional.

| key | default | what it does |
|---|---|---|
| `state_dir` | `"state"` | where shots, the log and hand-off files go (relative to `altshot.pyw`, or absolute) |
| `keep_shots` | `200` | older shots are deleted, oldest first |
| `redact` | `true` | the secret check; `false` saves shots unchecked and turns the clipboard door off |
| `ocr_language` | `"en-US"` | the recognizer language (must be installed in Windows) |
| `ocr_scales` | `[1, 2]` | read passes: as captured, then enlarged 2x (catches small text) |
| `ocr_timeout_s` | `4.0` | a shot whose check takes longer is withheld |
| `clipboard` | `true` | the clipboard door |
| `clipboard_timeout_s` | `6.0` | a clipboard image whose check takes longer is replaced by the withheld card |
| `screenshots_dir` | `""` | where your snipping tool saves; empty = Windows' own Screenshots folder |
| `handoff` | `true` | offer each shot to a companion app, if one is set up (below) |

Very large desktops take longer to check (about 1.3 s for three 1080p monitors, about 3 s at 10,400 pixels
wide). Raise the time limits if you run something that size.

## Optional: shots straight into Claude Code

The watcher works on its own. If you use Claude Code with mods, [`claude-code-mod/`](claude-code-mod) hands each
shot to the session you last typed in, as a draft in its prompt box (never sent), with the watcher's note of what
was hidden ("2 secrets hidden under black boxes"), never what it was.

1. Copy the `claude-code-mod` folder into `~/.claude/mods/` and name it `altshot`.
2. Set `ALTSHOT_STATE` at the top of `hooks/register.tsx` to your watcher's state folder (absolute path).

The hand-off itself is two small files, so any other app can use it too: the companion writes
`state/last.json` = `{"session": "<id>"}`, and the watcher answers each shot with
`state/pending/<id>.json` = `{path, at, hidden, secrets, random, withheld, note}`.

## What it can miss

Be honest with yourself about these:

- **A fast paste.** On the clipboard, the original sits there for the time the check takes (usually 0.1–0.5 s).
  A paste inside that window gets the original.
- **Apps that read the clipboard the instant it changes** (clipboard managers, Windows' clipboard history if you
  turn it on, sync tools) can keep the original. Keep Windows clipboard history off if this matters to you.
- **Tiny, faint or low-contrast text,** text inside a photo or a picture, and colours that turn grey-on-grey.
- **Non-Latin scripts** that your installed recognizer can't read. Long unreadable strings are hidden, short
  ones are not.
- **A secret split across lines** in a way no pattern sees. Wrapped keys are handled; other splits may not be.
- **Images copied together with text** (a rich copy from a browser or Office) are skipped on purpose, because
  replacing the image would break the text.
- **Image formats other than PNG and bitmap** on the clipboard are not checked.
- **The saved-file fix** only finds a file whose pixels match exactly, saved within about 13 seconds. It
  overwrites the file in place, which **does not wipe the old data from the disk**.
- **Anything that never passes through altshot or the clipboard** (another screenshot app that saves straight
  to a file, a screen recording, a screen share) is not checked.

Treat a screenshot of a secret as a leak to clean up: rotate the key.

## Tests

All tests use synthetic images with fake keys generated at runtime. They never capture your screen.

```
python tests/test_redaction.py
python tests/test_clipboard.py
```

`test_redaction.py` checks that every fake secret on 16 synthetic screens (two fonts, two sizes, four colour
themes) is fully covered with the right count, that clean screens trigger no rule, that wide screens and the
seams between their reading tiles are covered, and that the save path leaves no unchecked file behind.

**`test_clipboard.py` uses your real clipboard.** It saves everything on your clipboard first, puts its own test
images there for about 20 seconds, and then puts your clipboard back and checks the restore byte for byte (also
when a test fails). Don't copy anything while it runs. Data in handle-based formats (old metafiles and OLE
objects) can't be saved this way; the image and text formats can.

## Files

| file | what it is |
|---|---|
| `altshot.pyw` | the watcher: keyboard hook, capture, check, save, optional hand-off |
| `redact.py` | the OCR worker client, pattern matching, the pixel check, black boxes |
| `clipguard.py` | the clipboard door: listener, image read and write, saved-file fix |
| `ocr_worker.ps1` | the Windows OCR worker (pixels in over stdin, words out as JSON; nothing touches the disk) |
| `secret_patterns.json` | what counts as a secret |
| `altshot.config.example.json` | settings to copy and change |
| `claude-code-mod/` | the optional Claude Code hand-off |
| `tests/` | the tests above |

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Code & Chaos.
