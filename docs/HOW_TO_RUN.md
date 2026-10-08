# Aegis — how to run it, for someone who has never run code

This guide assumes nothing. It explains what the project is made of, how to
start it, and what every command does. Copy a command, paste it, press Enter.

---

## 1. What this project is

**Aegis is a security guard for one computer.** It checks how safe the computer
is, fixes weak settings with your permission, watches for attacks, and can block
or stop what it finds.

| | |
|---|---|
| **Language** | Python (version 3.11 or newer) |
| **Size** | ~14,700 lines of program code, ~7,000 lines of tests |
| **Runs on** | Windows, Linux, macOS |
| **Where it lives** | `D:\aegis` on this computer, and on GitHub |

Nothing runs on the internet. Everything happens on the computer you start it on.

---

## 2. Two ways to run it

### Way A — the installer (no Python needed)

Best for showing the project to somebody else.

1. Double-click `dist\installer\Aegis-Setup-2.1.0.exe`.
2. Windows may warn that the publisher is unknown. That is normal for software
   that has not been signed with a paid certificate: choose **More info → Run
   anyway**.
3. Aegis appears in the Start menu. Open it like any other program.

### Way B — from the source code (what a developer does)

This is how you run the code in `D:\aegis` directly.

**Open a terminal first.** Press the Windows key, type `powershell`, press Enter.
A black window appears. That is the terminal: you type commands, it answers.

**Step 1 — go to the project folder:**

```bash
cd D:\aegis
```

**Step 2 — start the app:**

```bash
.venv\Scripts\python -m aegis console
```

Aegis opens. That is all, because the project is already set up on this machine.

---

## 3. Setting it up on a *different* computer

If the `.venv` folder does not exist, the project has not been set up there yet.
Three steps, once:

**Step 1 — install Python** from <https://www.python.org/downloads/>. During
installation tick **"Add Python to PATH"**. Without that tick nothing below works.

**Step 2 — create a private workspace for the project** (this is the `.venv`
folder, a copy of Python that belongs only to Aegis, so it cannot disturb
anything else on the computer):

```bash
cd D:\aegis
python -m venv .venv
```

**Step 3 — install Aegis and the libraries it uses:**

```bash
.venv\Scripts\python -m pip install -e ".[dev]"
```

That reads `pyproject.toml`, the project's shopping list, and downloads what it
names: `psutil` (reads programs and connections), `flet` (draws the window),
`scikit-learn` (the machine-learning assist), and a few more.

It takes a few minutes and needs the internet. After that, everything is local.

---

## 4. The commands, and what each one does

Every command starts with `.venv\Scripts\python -m aegis` from inside `D:\aegis`.

| Command | What happens |
|---|---|
| `... -m aegis console` | Opens the app window. **Start here.** |
| `... -m aegis check` | Checks the computer's security settings and prints a score out of 100 |
| `... -m aegis harden` | Lists weaknesses that Aegis can fix, and the exact change each fix makes |
| `... -m aegis harden apply FIX-WIN-SMB1` | Applies one fix, after showing you what it changes and asking |
| `... -m aegis harden undo 1` | Undoes fix number 1 |
| `... -m aegis harden apply-safe` | Applies every fix that cannot lock you out, after showing you all of them |
| `... -m aegis vulns check` | Asks the public vulnerability database whether any installed program has a known flaw. Slow: the database allows only a few questions per minute |
| `... -m aegis vulns report` | Shows what that check found last time, without using the internet |
| `... -m aegis monitor` | Watches the computer in the terminal, printing anything suspicious. Press `Ctrl+C` to stop |
| `... -m aegis serve` | Opens the web dashboard in your browser |
| `... -m aegis report` | Writes a shareable HTML report you can email or print |
| `... -m aegis status` | One screen: version, privileges, whether anything is watching |
| `... -m aegis autostart enable` | Makes Aegis watch automatically whenever you sign in |
| `... -m aegis stop 1234` | Stops the program running as process 1234 |
| `... -m aegis quarantine <file>` | Moves a suspicious file somewhere safe (never deletes it) |
| `... -m aegis --help` | Lists everything |

**A shorter way:** after `.venv\Scripts\activate` you can type just `aegis check`
instead of the long form. `deactivate` undoes it.

---

## 5. What the folders contain

```
D:\aegis\
├── aegis\              THE PROGRAM ITSELF
│   ├── collectors\     watches: connections, programs, files, sign-ins, DNS
│   ├── detection\      decides what is suspicious (the rules)
│   ├── posture\        the security check
│   ├── hardening\      the fixes, and undo
│   ├── response\       blocking, stopping, quarantine
│   ├── storage\        the database
│   ├── ui\             the app window
│   ├── api\            the web dashboard
│   └── cli.py          the commands above
├── tests\              proves the program works (870 automatic tests)
├── docs\               architecture, detections, threat model, this guide
├── packaging\          builds the Windows installer
├── dist\               the built app and installer
└── pyproject.toml      the list of libraries the project needs
```

**Reading order, if you want to understand the code:** `aegis/cli.py` (what each
command does) → `aegis/service.py` (the conductor that connects everything) →
`aegis/detection/rules/` (the detections, each one small and self-contained).

---

## 6. Where Aegis keeps its data

`C:\Users\<you>\AppData\Local\Aegis`

| File | Holds |
|---|---|
| `aegis.db` | alerts, detections, audit trail, fix history |
| `config.json` | your settings |
| `logs\aegis.log` | a diary of what Aegis did |
| `quarantine\` | files that were moved out of the way |

Deleting that folder resets Aegis completely. Nothing there leaves the computer.

---

## 7. Checking the project is healthy

```bash
.venv\Scripts\python -m pytest          # runs 870 tests; all must pass
.venv\Scripts\python -m ruff check aegis tests    # checks code style
.venv\Scripts\python -m mypy            # checks for type mistakes
```

Useful before a demo: if the tests pass, the project works.

---

## 8. When something goes wrong

| What you see | What it means |
|---|---|
| `python is not recognized` | Python is not installed, or "Add to PATH" was not ticked |
| `No module named aegis` | You are not in `D:\aegis`, or step 3 of setup was skipped |
| `Collector 'auth' unavailable` | Normal. Reading the Windows sign-in log needs administrator rights |
| `Refusing to attempt a block without privileges` | Normal. Firewall changes need administrator rights: right-click PowerShell → Run as administrator |
| The window does not open | Another Aegis may already be running. Close it, or check `aegis status` |

---

## 9. Explaining it in a viva, in four sentences

> Aegis is an endpoint security tool written in Python that protects a single
> computer. It runs 17 read-only checks of the machine's security settings and
> scores them, then fixes the weak ones through a flow that explains the risk,
> asks permission, backs up, applies, verifies and can undo. While running it
> watches network connections, programs, files, sign-ins and DNS lookups against
> 33 detection rules mapped to MITRE ATT&CK, and can block an address, stop a
> program or quarantine a file. Every action it takes is recorded in an audit
> trail, and 870 automated tests run on Windows, Linux and macOS on every change.
