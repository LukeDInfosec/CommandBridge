# Command Bridge v5

A PyQt6 control surface for pentest tooling: one window that drives nmap,
rustscan, ffuf, sqlmap, nuclei, the gau/gf/uro/Gxss/kxss XSS chain and about
forty other command-line tools, with live console output, editable command
templates and per-engagement output directories.

---

## Running it

```bash
python3 command_bridge_v5.py
```

Requires Python 3.9+ and PyQt6:

```bash
sudo apt install -y python3-pyqt6 git
```

The external scanning tools are installed from inside the app: **Target Setup
→ Environment / Tool Setup → Install / Repair Missing Tools**. That script
(`command_bridge/modules/install_tools.sh`) handles apt, pipx, `go install` and
clone-and-wrap installs, copies Go/pipx binaries into `~/.local/bin`, and
repairs pipx tools broken by a system Python upgrade. It is safe to re-run.

---

## Updating

This copy updates itself. **Target Setup → Software Updates → Check for
Updates** fetches from the remote, lists the incoming commits, and — once you
confirm — fast-forwards and restarts in place.

It only ever fast-forwards. If the box has local commits or edited tracked
files, the update stops and tells you rather than overwriting your work.

### One-time setup on a new box

The updater needs the install directory to be a git clone rather than an
unzipped folder:

```bash
cd ~/Desktop/Luke_Software
git clone https://github.com/<you>/command-bridge.git CommandBridge
cd CommandBridge
python3 command_bridge_v5.py
```

For a **private** repository, give the box a read-only credential once:

```bash
git config --global credential.helper store
git clone https://github.com/<you>/command-bridge.git CommandBridge
# username: your GitHub username
# password: a fine-grained PAT with Contents: READ-ONLY on this repo
```

Use a **read-only** token here. The box only ever pulls, so a write token on a
machine you take onto client sites buys nothing and risks your tooling being
rewritten. `credential.helper store` writes it to `~/.git-credentials` in
plaintext — `chmod 600 ~/.git-credentials` and treat that box accordingly, or
use an SSH deploy key instead if you prefer.

---

## What survives an update

Everything you customise lives in `~/.config/CommandBridge`, outside the repo,
and is never touched by a pull:

| File | Holds |
|---|---|
| `commands.json` | command templates you have edited in-app |
| `preferences.json` | theme, output directory, target history |
| `sections.json` | which cards are collapsed |
| `errors.log` | crash log written by the global exception guard |

Scan output is written to the output directory you choose on the Target tab.
`.gitignore` also excludes the common result filenames so a scan run from
inside the install folder can never end up committed.

---

## Layout

```
command_bridge_v5.py          launcher
command_bridge/
  constants.py                design tokens, tab registry, 17 colour palettes
  ui/                         window chrome, theme engine, the nine tabs
  core/                       command execution, output, status bar, updater
  modules/                    per-tool logic + install_tools.sh
  widgets/                    console pane, process runner
smartfuzz.py, param_finder.sh helper scripts invoked by buttons
verify_tool_coverage.py       checks every tool a button calls is installable
```

## Keeping the installer honest

Adding a button that shells out to a new tool means adding that tool to
`install_tools.sh`. Nothing in the code enforces that link, so it is checked:

```bash
python3 verify_tool_coverage.py
```

It re-derives the tool list from the command templates and exits non-zero if
anything a button calls is missing from the installer. Worth running before
any push that adds or changes a button.
