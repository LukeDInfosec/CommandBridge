# Command Bridge — session handover

Context for a fresh Claude session picking up this project. Written
2026-09-16.

---

## Who and what

**Luke** (LukeDInfosec) is a penetration tester. **Command Bridge v5** is his
own PyQt6 GUI that drives command-line pentest tooling — one window with nine
tabs of buttons, each wired to an editable shell command template, streaming
into a live console. Usage split is roughly 98% pentesting, 2% bug bounty, all
on authorised engagements.

**Where it lives**

| | |
|---|---|
| Runs on | Kali, `/home/ldawson/Desktop/Luke_Software/Test26` |
| Mirrored on | Windows laptop, `C:\Users\luke_\Desktop\Luke_Software\Test26` (connected to Cowork sessions) |
| Repo | `https://github.com/LukeDInfosec/CommandBridge` (private) |
| Entry point | `python3 command_bridge_v5.py`, or `launch.sh` |

The Kali box is **not** linked to Cowork sessions — only the Windows laptop's
folder is. That asymmetry is why the GitHub workflow below exists.

---

## Architecture

`CommandBridgeV5` in `command_bridge/ui/window.py` composes ~39 mixin classes.
Nothing subclasses anything except `QMainWindow`; every feature is a mixin.

```
command_bridge_v5.py          launcher
command_bridge/
  constants.py                design tokens, TABS registry, 17 THEMES
  main.py                     app bootstrap + global sys.excepthook guard
  ui/
    window.py                 the mixin composition — start here
    theme.py                  QSS generated from the active palette
    cards.py                  create_card, collapsible sections, editable buttons
    icons.py                  QPainter-drawn icon set (no emoji/icon font)
    navigation.py             header, nav rail, status bar, tab registry
    tabs_*.py                 the nine tabs
  core/
    commands.py               placeholder substitution + execution
    output.py                 process output handling, completion handler
    status.py                 status bar, action naming, completion messages
    updater.py                self-update (git fetch/ff-merge/restart)
    preferences.py            ~/.config/CommandBridge persistence
  modules/                    per-tool logic, install_tools.sh, crtsh.py
  widgets/                    console pane, QProcess runner
smartfuzz.py, param_finder.sh  helper scripts invoked by buttons
verify_tool_coverage.py        installer-coverage check (see below)
```

### Things that will bite you

* **PyQt6 aborts the process on an unhandled exception in a slot.** A single
  bad dict key once killed the app every time a scan finished. `main.py`
  installs a `sys.excepthook` that logs to `~/.config/CommandBridge/errors.log`
  and prints into the console pane instead of dying. Do not remove it.
* **Python evaluates default arguments eagerly.** `THEMES.get(name,
  THEMES["Deleted Theme"])` raises `KeyError` before `.get` ever runs. That
  was the crash above. Use `self.theme()`.
* **Qt eats a lone `&`** in button and groupbox text as a mnemonic marker. It
  must be escaped to `&&` — and that escape makes Qt measure a wider title
  than it paints, drifting the text right. `_ampersand_shift()` in `theme.py`
  measures and cancels that per ampersand.
* **HTML in QTextEdit collapses runs of spaces**, which destroys ASCII art.
  `widgets/console.py` substitutes `&nbsp;` runs.
* **Never hardcode a tab index.** Use `self.goto_tab("console")` against the
  `TABS` registry in `constants.py`.
* **Never hardcode a colour.** Every colour comes from the active palette.

### Placeholders in command templates

| Placeholder | Becomes |
|---|---|
| `{TARGET}` | the target exactly as entered, scheme and path included |
| `{TARGET_HOST}` | bare hostname — for tools that reject a URL |
| `{SAFE_TARGET}` | filename-safe form, used for output files |
| `{CB_DIR}` | install directory, for calling bundled scripts |

Getting `{TARGET}` vs `{TARGET_HOST}` wrong is the single most common source
of "this button doesn't work" — subfinder, gau, rustscan, dnsx and
theHarvester all need the bare host.

---

## What has been done

**Full UI redesign.** Navigation rail, header breadcrumb, status bar, drawn
icon set, 17 colour palettes (Graphite default; includes Black & Orange,
Cyber Neon, Deep Ocean, Sandstone). Tab order follows an engagement:
ENGAGE → DISCOVER → TEST → ANALYSE, with Console and Bounty pinned.

**Alignment pass.** Card titles, menu section headings and nav rail captions
all sit on one 20px left rail, verified by measuring rendered geometry under
Xvfb rather than by eye. Collapsible cards put the chevron in the gutter.

**Command audit.** All 180 command templates extracted by AST and checked;
masscan replaced by RustScan (with an nmap hand-off), plus fixes to hakrawler
`-d`, ghauri logging, nuclei template paths, gau `--subs`, and several
`{TARGET}` → `{TARGET_HOST}` corrections.

**Installer coverage.** `install_tools.sh` now handles all 43 tools any button
invokes — apt, pipx, `go install`, and clone-and-wrap for Corsy, SSRFmap and
SSTImap. `verify_tool_coverage.py` re-derives the tool list from the command
templates and fails if anything a button calls is missing from the installer.

**Self-update.** Target Setup → Software Updates. `git fetch`, show incoming
commits, fast-forward, restart in place. Only ever fast-forwards; refuses on
local commits or modified tracked files and explains why.

**Latest fixes (commit not yet in the repo — see below).** Friendly action
names in the console ("Tool Status Check has been completed", not
"[install_tools.sh]"); wafw00f stale-pip-shim repair; `crtsh.py` replacing a
fragile inline JSON pipe; "Retrieve JS Files" and "Analyse Downloaded JS"
merged into "Retrieve & Analyse JS Files".

---

## Current state

The repo has Luke's seed commit. **One commit of work is not yet pushed** —
it exists in this container and as `0001-commandbridge-fixes.patch`, which is
in his Windows `Test26` folder.

### The blocker

Cowork's egress proxy refuses all git access to the repo:

> `LukeDInfosec/CommandBridge is not in this session's authorized repository
> set, so the proxy will not inject a credential for it. To fix, add the
> repository to the session's sources.`

Both push and read are refused. Supplying a personal access token does not
help — the proxy uses its own credential and simply declines repos outside the
session's list. Installing the GitHub connector mid-session did not help
either, which suggests the authorized set is fixed when a session starts.
**Unverified theory: a new task started with the repo attached as a source
should work.** Test it cheaply with `git ls-remote`.

Do not try to route around this. It is an organisation egress policy.

### Getting the outstanding commit in

On Kali, with a temporary write token that is deleted afterwards:

```bash
cd ~/Desktop/Luke_Software/Test26
git am < 0001-commandbridge-fixes.patch
git push origin main
```

---

## Working agreements with Luke

* **Verify everything before delivering.** His words: *"Please troubleshoot
  all commands before giving me the files updated as I can't keep reporting
  one after another."* Run the harness, don't fix reported bugs one at a time.
* **Be honest about the strength of evidence.** Say which things were
  executed and which were only documentation-verified. Several Go tools and
  crt.sh cannot be reached from the sandbox.
* **It must look like enterprise software.** No emoji in the UI, no raw
  binary names in user-facing text, consistent typography and alignment.
* **Secrets.** He has pasted tokens into chat twice; both were revoked. Do
  not ask for a token — the box needs a **read-only** one typed directly into
  its own terminal, never relayed through chat.
* **Delivery.** Historically: build zip → `SendUserFile` → `device_commit_files`
  with the returned `fileUuid` to the Windows path. The whole point of the
  GitHub work is to retire that loop.

## Verification harness

Not part of the deliverable; lives in the container's home directory.

| Script | Checks |
|---|---|
| `extract_commands.py` | AST-extracts all 180 command templates to `commands.json` |
| `validate_commands.py` | executes each against localhost, classifies failures |
| `audit.py` | resolves all 613 `self.X()` calls against a live window |
| `final_check.py` | runtime smoke: scan → theme cycle → stop → clear → restart → close mid-scan |

Plus, in the repo, `python3 verify_tool_coverage.py`.

Run the app headless with `xvfb-run -a python3 ...`; `window.grab().save(path)`
gives a screenshot for visual checks.

## What survives an update

Everything Luke customises lives in `~/.config/CommandBridge` — edited command
templates, theme, output directory, collapsed sections, error log. It is
outside the repo and a pull never touches it. `.gitignore` also excludes
`__pycache__` (otherwise the tree is permanently dirty and the updater blocks
itself) and the usual scan-output filenames, since his output directory
sometimes points at the install folder.
