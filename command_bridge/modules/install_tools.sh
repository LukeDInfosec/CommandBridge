#!/bin/bash
# install_tools.sh — checks (and, unless --check-only, best-effort installs
# or repairs) every external command-line tool Command Bridge's buttons call.
#
# Why this exists: on a real Kali box, two failure modes account for almost
# every "command not found" / "bad interpreter" error the buttons hit —
#   1) pipx-installed tools (droopescan, uro, graphql-cop, ...) whose venv
#      shim points at a Python interpreter that no longer exists, usually
#      after a system Python version upgrade. `command -v <tool>` still
#      finds the shim FILE, so a plain existence check says "installed" even
#      though every invocation fails with "bad interpreter: No such file or
#      directory". `pipx install --force <tool>` rebuilds the venv against
#      the current interpreter and fixes this in one shot.
#   2) Go-based recon tools (gau, gf, Gxss, kxss, dalfox, ...) that were
#      simply never installed on a fresh box.
#
# Usage:
#   bash install_tools.sh              # check, then install/repair anything missing or broken
#   bash install_tools.sh --check-only # check only — changes nothing on disk
#
# Safe to re-run any time: every tool is handled independently (set +e), so
# one tool failing to install never skips the rest, and re-running after a
# partial run just re-checks what's already fixed and retries the rest.

set +e
CHECK_ONLY=0
[ "$1" = "--check-only" ] && CHECK_ONLY=1

declare -a OK_LIST=() FIXED_LIST=() FAILED_LIST=() MISSING_LIST=() SKIPPED_LIST=()

mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"

HAVE_GO=0
command -v go >/dev/null 2>&1 && HAVE_GO=1
GOBIN="$(go env GOPATH 2>/dev/null)/bin"
[ -z "$GOBIN" ] && GOBIN="$HOME/go/bin"
export PATH="$PATH:$GOBIN"

HAVE_PIPX=0
command -v pipx >/dev/null 2>&1 && HAVE_PIPX=1

TOOLS_DIR="$HOME/.local/share/command-bridge-tools"
mkdir -p "$TOOLS_DIR"

# ── helpers ──────────────────────────────────────────────────────────────

hr() { printf '%.0s-' $(seq 1 70); echo; }

# _last_meaningful_line <text>
#
# The useful part of a failure is almost always the last line: a Python
# traceback ends on the exception, and a shell exec failure is a single line.
# Pulling that out beats matching a list of phrases, which was fragile and
# quietly produced nothing when the wording differed.
_last_meaningful_line() {
    printf '%s\n' "$1" \
        | grep -vE '^\s*$|^\s*File "|^\s*\^+\s*$|^\s*~+\^*~*\s*$|Traceback \(most recent' \
        | tail -1 \
        | sed 's/^[[:space:]]*//' \
        | cut -c1-100
}

# check_tool <bin> [test-flag] -> prints: ok | missing | broken|<reason>
#
# The reason rides on the same line because check_tool is always called inside
# a command substitution, which is a subshell — a variable set in here never
# reaches the caller, which is why the reason came back empty at first.
check_tool() {
    local bin="$1" flag="${2:---help}"
    local path
    path="$(command -v "$bin" 2>/dev/null)"
    if [ -z "$path" ]; then
        echo "missing"
        return
    fi
    local out
    out="$(timeout 8 "$bin" "$flag" 2>&1)"
    # The exact wording bash/coreutils use for "this file exists but can't
    # actually be executed" (a rotted pipx-venv shebang being the classic
    # cause) is NOT consistent across systems, so match every phrasing we've
    # actually observed rather than one exact string:
    #   - "bad interpreter: No such file or directory"   (classic glibc bash,
    #     e.g. the droopescan error this app was built to catch)
    #   - "cannot execute: required file not found"      (some bash builds,
    #     printed when `bin` itself is exec'd and fails)
    #   - "failed to run command"                        (coreutils `timeout`
    #     itself reporting the same underlying exec failure, since we run
    #     the tool *through* timeout above)
    # A working tool's own --help output essentially never contains any of
    # these phrases, so this stays safe against false positives.
    if echo "$out" | grep -qiE 'bad interpreter|cannot execute|required file not found|failed to run command'; then
        echo "broken|$(_last_meaningful_line "$out")"
        return
    fi
    # A Python tool that dies before it can print its own --help is just as
    # broken, and this is the second failure mode a Kali box reliably
    # produces: a pip-installed console script in /usr/local/bin pinned to an
    # old version ("wafw00f==2.2.0") shadowing the apt package that actually
    # got upgraded, so every run ends in DistributionNotFound or
    # VersionConflict. A working tool's --help never contains a traceback.
    if echo "$out" | grep -qE 'Traceback \(most recent call last\)|DistributionNotFound|VersionConflict|ModuleNotFoundError|ImportError:'; then
        local reason
        reason="$(_last_meaningful_line "$out")"
        [ -z "$reason" ] && reason="python error on startup"
        echo "broken|$reason"
        return
    fi
    echo "ok"
}

# fix_stale_pip_shim <bin>
#
# Repairs the "/usr/local/bin shadows the real package" failure. pip (and old
# easy_install) drop a console script into /usr/local/bin that hard-codes the
# version it was installed against:
#
#     __import__('pkg_resources').run_script('wafw00f==2.2.0', 'wafw00f')
#
# When the tool is later upgraded — or reinstalled from apt into
# /usr/lib/python3/dist-packages — that pinned version no longer exists, but
# /usr/local/bin still comes first on PATH, so every invocation raises
# DistributionNotFound. The apt-installed copy is sitting right there in
# /usr/bin, unused.
#
# The shim is renamed rather than deleted, so nothing is destroyed and the
# change can be undone by moving it back.
fix_stale_pip_shim() {
    local bin="$1" shim other
    shim="$(command -v "$bin" 2>/dev/null)"
    [ -n "$shim" ] || return 1

    # Only ever touch /usr/local/bin — a distro-managed binary is not ours
    # to move, and a pipx shim in ~/.local/bin is handled by pipx_install.
    case "$shim" in
        /usr/local/bin/*) ;;
        *) return 1 ;;
    esac

    # It must actually look like a Python entry-point script.
    grep -qE 'pkg_resources|importlib.metadata|EntryPoint' "$shim" 2>/dev/null || return 1

    # And there must be another copy for PATH to fall back to, or renaming
    # this one just removes the tool entirely.
    other="$(type -aP "$bin" 2>/dev/null | grep -v "^${shim}$" | head -1)"
    if [ -z "$other" ]; then
        echo "$shim looks like a stale pip shim, but there is no other copy of $bin to fall back to -- leaving it alone."
        return 1
    fi

    echo "[*] $shim is a stale pip shim shadowing $other -- renaming it to ${shim}.cb-disabled"
    if run_privileged mv -f "$shim" "${shim}.cb-disabled"; then
        return 0
    fi
    # Nothing here can escalate, so hand over the one command that fixes it
    # rather than failing with a raw sudo error.
    echo "[!] Could not rename it — this needs root and there is no terminal"
    echo "    for sudo to prompt on. Run this once, then re-check:"
    echo "        sudo mv -f '$shim' '${shim}.cb-disabled'"
    return 1
}

report() {
    local name="$1" status="$2" detail="$3"
    case "$status" in
        ok)      OK_LIST+=("$name");      echo "  [OK]      $name" ;;
        fixed)   FIXED_LIST+=("$name");   echo "  [FIXED]   $name" ;;
        failed)  FAILED_LIST+=("$name");  echo "  [FAILED]  $name${detail:+ -- $detail}" ;;
        missing) MISSING_LIST+=("$name"); echo "  [MISSING] $name${detail:+ -- $detail}" ;;
        broken)  MISSING_LIST+=("$name"); echo "  [BROKEN]  $name${detail:+ -- $detail}" ;;
        skipped) SKIPPED_LIST+=("$name"); echo "  [SKIPPED] $name${detail:+ -- $detail}" ;;
    esac
}

# Packages that need apt but could not be installed, collected so the run can
# end with ONE command to paste rather than a failure per tool.
declare -a APT_DEFERRED=()

# run_privileged <command...>
#
# Anything needing root goes through here. Launched from the GUI there is no
# terminal for sudo to prompt on — plain `sudo` just prints "a terminal is
# required to read the password" and fails — so cached/NOPASSWD sudo is tried
# first, then pkexec, which raises the desktop's own password dialog.
run_privileged() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
        return
    fi
    if sudo -n true 2>/dev/null; then
        sudo -n "$@"
        return
    fi
    if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v pkexec >/dev/null 2>&1; then
        pkexec "$@"
        return
    fi
    return 1
}

# apt_install <package>
#
# This script is normally launched from the GUI, where there is no terminal
# for sudo to prompt on — "sudo: a terminal is required to read the password"
# is what a plain `sudo apt-get` produces there, and it failed every apt tool.
#
# So, in order of how little it bothers the user:
#   1. already root, or sudo is cached / NOPASSWD  -> just do it
#   2. a desktop session is present                -> pkexec, which opens the
#      system's own password dialog
#   3. neither                                     -> defer it, and print one
#      apt-get line at the end covering everything that needs it
apt_install() {
    local pkg="$1"

    if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then
        run_privileged apt-get install -y "$pkg"
        return
    fi

    if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v pkexec >/dev/null 2>&1; then
        echo "[*] Requesting authorisation to install $pkg (a password dialog should appear)…"
        if run_privileged apt-get install -y "$pkg"; then
            return
        fi
        echo "[!] The authorisation dialog was dismissed or failed."
    fi

    APT_DEFERRED+=("$pkg")
    echo "[!] $pkg needs apt, and there is no terminal here for sudo to prompt on."
    echo "    It has been added to the summary at the end of this run."
    return 1
}

pipx_install() {
    local tool="$1"
    if [ "$HAVE_PIPX" = "0" ]; then
        echo "pipx is not installed -- install it first with: sudo apt install -y pipx"
        return 1
    fi

    # `pipx install --force` is NOT safe against a venv whose Python
    # interpreter has been deleted out from under it (e.g. after a Kali
    # system Python upgrade, which is exactly the droopescan/uro failure
    # mode this script exists to fix) — pipx's own reinstall codepath tries
    # to spawn the OLD venv's python as part of the reinstall and crashes
    # with an uncaught FileNotFoundError instead of just rebuilding the
    # venv (a known long-standing pipx bug: pypa/pipx#146, #294). Newer pipx
    # ships `pipx repair`, purpose-built for this exact scenario (rebuilds
    # the venv from recorded install metadata without needing the broken
    # interpreter), so try that first.
    if pipx repair "$tool" >/dev/null 2>&1; then
        if command -v "$tool" >/dev/null 2>&1 && timeout 8 "$tool" --help >/dev/null 2>&1; then
            return 0
        fi
    fi

    # Either this pipx is too old to have `repair`, the tool was never
    # installed at all (repair is a no-op for that), or repair couldn't
    # fully fix it. Fall back to removing any broken venv/shim by hand so a
    # plain install starts clean instead of touching whatever made it crash.
    rm -rf "$HOME/.local/share/pipx/venvs/$tool" 2>/dev/null
    rm -f "$HOME/.local/bin/$tool" 2>/dev/null
    pipx install "$tool"
}

# git_script_install <bin-name> <repo-url> <entry-script> [pip-packages...]
#
# For the handful of tools this app calls that have no apt package, no PyPI
# release and no Go module — they are just a repo you clone and run a script
# out of (Corsy, SSRFmap, SSTImap). The repo is cloned once into TOOLS_DIR and
# a tiny wrapper goes into ~/.local/bin so the button's command can call the
# tool by plain name (`corsy -u ...`) exactly like any packaged tool.
git_script_install() {
    local bin="$1" repo="$2" entry="$3"
    shift 3
    local dir="$TOOLS_DIR/$bin"

    if [ ! -d "$dir/.git" ]; then
        rm -rf "$dir"
        git clone --depth 1 "$repo" "$dir" || return 1
    else
        git -C "$dir" pull --ff-only >/dev/null 2>&1
    fi

    if [ ! -f "$dir/$entry" ]; then
        echo "clone succeeded but $entry is not in the repo -- upstream layout changed?"
        return 1
    fi

    # Dependencies: prefer the repo's own requirements.txt, otherwise the
    # explicit package list the caller passed. --break-system-packages is
    # needed on Kali's externally-managed Python; the plain call is the
    # fallback for older systems that reject the flag.
    if [ -f "$dir/requirements.txt" ]; then
        pip3 install --user --break-system-packages -r "$dir/requirements.txt" >/dev/null 2>&1 \
            || pip3 install --user -r "$dir/requirements.txt" >/dev/null 2>&1
    fi
    if [ "$#" -gt 0 ]; then
        pip3 install --user --break-system-packages "$@" >/dev/null 2>&1 \
            || pip3 install --user "$@" >/dev/null 2>&1
    fi

    cat > "$HOME/.local/bin/$bin" <<EOF
#!/bin/bash
# Generated by Command Bridge install_tools.sh -- wrapper for $repo
cd "$dir" || exit 1
exec python3 "$dir/$entry" "\$@"
EOF
    chmod +x "$HOME/.local/bin/$bin"
}

go_install_to_local_bin() {
    # $1 = module path (e.g. github.com/x/y@latest), $2 = binary name it produces
    if [ "$HAVE_GO" = "0" ]; then
        echo "Go is not installed -- install it first with: sudo apt install -y golang-go"
        return 1
    fi
    go install "$1" || return 1
    if [ -f "$GOBIN/$2" ]; then
        cp -f "$GOBIN/$2" "$HOME/.local/bin/$2"
    else
        echo "go install reported success but $GOBIN/$2 was not found"
        return 1
    fi
}

# handle_tool <display-name> <binary-to-check> <installer-function-name> [test-flag]
handle_tool() {
    local name="$1" bin="$2" installer="$3" flag="${4:---help}"
    local status raw why
    raw="$(check_tool "$bin" "$flag")"
    status="${raw%%|*}"
    why=""
    [ "$raw" != "$status" ] && why="${raw#*|}"

    if [ "$status" = "ok" ]; then
        report "$name" ok
        return
    fi

    if [ "$CHECK_ONLY" = "1" ]; then
        # "[BROKEN] dirsearch" on its own says nothing. The reason was already
        # captured while checking — show it.
        report "$name" "$status" "$why"
        return
    fi

    echo "  [*] $name: $status -- attempting install/repair..."

    # A stale /usr/local/bin pip shim shadowing a working package is cheap to
    # test for and cheap to fix, and when it is the cause no install is needed
    # at all — so try it before reaching for apt/pipx/go. Applies to every
    # tool, not just the one that surfaced it.
    [ -n "$why" ] && echo "      reason: $why"

    if [ "$status" = "broken" ] && fix_stale_pip_shim "$bin" >/dev/null 2>&1; then
        if [ "$(check_tool "$bin" "$flag")" = "ok" ]; then
            report "$name" fixed "removed a stale pip shim from /usr/local/bin"
            return
        fi
    fi

    local log
    log="$(mktemp /tmp/cb_install_XXXXXX.log)"
    "$installer" >"$log" 2>&1

    # bash caches the path of every command it has run, so a tool that has
    # just been reinstalled somewhere earlier on PATH still resolves to the
    # old broken copy. That is why droopescan reported FAILED immediately
    # after pipx said "installed package droopescan 1.45.1". Forget the
    # cached paths before re-checking.
    hash -r 2>/dev/null

    local newstatus
    newstatus="$(check_tool "$bin" "$flag")"
    newstatus="${newstatus%%|*}"
    if [ "$newstatus" = "ok" ]; then
        report "$name" fixed
        rm -f "$log"
    else
        report "$name" failed "log: $log"
        tail -6 "$log" | sed 's/^/      /'
    fi
}

# ── per-tool installers ──────────────────────────────────────────────────

_i_nmap()        { apt_install nmap; }
_i_masscan()     { apt_install masscan; }
_i_rustscan()    {
    # RustScan isn't in most distro repos, so: apt if it happens to be
    # packaged, then the upstream .deb release, then cargo.
    apt_install rustscan && command -v rustscan >/dev/null 2>&1 && return 0

    local deb url
    deb="$(mktemp /tmp/rustscan_XXXXXX.deb)"
    url="$(curl -fsSL https://api.github.com/repos/bee-san/RustScan/releases/latest 2>/dev/null \
           | grep -oE 'https://[^"]+amd64\.deb' | head -n1)"
    if [ -n "$url" ] && curl -fsSL "$url" -o "$deb" 2>/dev/null; then
        if [ "$(id -u)" = "0" ]; then
            dpkg -i "$deb" >/dev/null 2>&1
        elif sudo -n true 2>/dev/null; then
            sudo -n dpkg -i "$deb" >/dev/null 2>&1
        else
            echo "[*] Installing rustscan via sudo dpkg — you may be prompted for your password:"
            sudo dpkg -i "$deb"
        fi
        rm -f "$deb"
        command -v rustscan >/dev/null 2>&1 && return 0
    fi
    rm -f "$deb"

    if command -v cargo >/dev/null 2>&1; then
        cargo install rustscan
    else
        echo "rustscan: no apt package, .deb download failed, and cargo is not installed."
        echo "  Install manually: https://github.com/bee-san/RustScan/releases"
        return 1
    fi
}
_i_hping3()      { apt_install hping3; }
_i_nikto()       { apt_install nikto; }
_i_ike_scan()    { apt_install ike-scan; }
_i_dotdotpwn()   { apt_install dotdotpwn; }
# wafw00f is the tool this bites most often: Kali ships 2.4.2 in
# dist-packages while an old pip install leaves a /usr/local/bin/wafw00f
# pinned to 2.2.0 ahead of it on PATH. Clear that first — if it was the only
# problem the tool is already working and nothing needs installing.
_i_wafw00f() {
    if fix_stale_pip_shim wafw00f; then
        [ "$(check_tool wafw00f)" = "ok" ] && return 0   # status word only; "broken|…" never equals "ok"
    fi
    apt_install wafw00f || pipx_install wafw00f
}

# ssh-audit is packaged, but the pipx release is usually newer and the apt
# one is occasionally held back, so fall through rather than giving up.
_i_ssh_audit()   { apt_install ssh-audit || pipx_install ssh-audit; }

# Kali's package is "theharvester" (lowercase) but the binary it installs is
# "theHarvester" (capital H) -- the lowercase name is a deprecated alias that
# prints a warning. The buttons call the capitalised name, which is why
# handle_tool checks "theHarvester" while this installs "theharvester".
_i_theharvester() { apt_install theharvester; }
_i_ffuf()        { apt_install ffuf; }
_i_gobuster()    { apt_install gobuster; }
_i_feroxbuster() { apt_install feroxbuster; }
_i_dirsearch()   { apt_install dirsearch; }
_i_wfuzz()       { apt_install wfuzz; }
_i_sqlmap()      { apt_install sqlmap; }
_i_nuclei()      { apt_install nuclei || go_install_to_local_bin github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei; }
_i_whatweb()     { apt_install whatweb; }
_i_arjun()       { pipx_install arjun; }
_i_wpscan()      { apt_install wpscan; }
_i_droopescan()  { pipx_install droopescan; }
_i_graphql_cop() { pipx_install graphql-cop; }
_i_amass()       { apt_install amass; }
# ghauri has never been published to PyPI — "pip install ghauri" fails with
# "No matching distribution found". It installs from its own repository.
_i_ghauri() {
    if [ "$HAVE_PIPX" = "1" ]; then
        rm -rf "$HOME/.local/share/pipx/venvs/ghauri" 2>/dev/null
        pipx install --force "git+https://github.com/r0oth3x49/ghauri.git" && return 0
    fi
    git_script_install ghauri https://github.com/r0oth3x49/ghauri.git ghauri.py
}
_i_urldedupe()   { go_install_to_local_bin github.com/ameenmaali/urldedupe@latest urldedupe; }

_i_testssl() {
    apt_install testssl.sh
    # Kali's package provides the binary as testssl.sh — this app calls the
    # bare "testssl" name, so symlink it if only the .sh name exists.
    if ! command -v testssl >/dev/null 2>&1 && command -v testssl.sh >/dev/null 2>&1; then
        ln -sf "$(command -v testssl.sh)" "$HOME/.local/bin/testssl"
    fi
}

_i_gau() { apt_install gau || go_install_to_local_bin github.com/lc/gau/v2/cmd/gau@latest gau; }
_i_waybackurls() { apt_install waybackurls || go_install_to_local_bin github.com/tomnomnom/waybackurls@latest waybackurls; }
_i_uro() { pipx_install uro; }
_i_Gxss() { go_install_to_local_bin github.com/KathanP19/Gxss@latest Gxss; }
_i_kxss() { go_install_to_local_bin github.com/Emoe/kxss@latest kxss; }
_i_dalfox() { apt_install dalfox || go_install_to_local_bin github.com/hahwul/dalfox/v2@latest dalfox; }
_i_katana() { apt_install katana || go_install_to_local_bin github.com/projectdiscovery/katana/cmd/katana@latest katana; }
_i_subfinder() { apt_install subfinder || go_install_to_local_bin github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder; }

_i_gf() {
    apt_install gf || go_install_to_local_bin github.com/tomnomnom/gf@latest gf
}

_i_dnsx()      { apt_install dnsx || go_install_to_local_bin github.com/projectdiscovery/dnsx/cmd/dnsx@latest dnsx; }
_i_hakrawler() { apt_install hakrawler || go_install_to_local_bin github.com/hakluke/hakrawler@latest hakrawler; }

# subzy moved from LukaSikic/subzy to PentestPad/subzy; the old path no
# longer resolves, so only the current one is used.
_i_subzy()     { go_install_to_local_bin github.com/PentestPad/subzy@latest subzy; }

# LFImap publishes to PyPI as "lfimap" with an lfimap console script. If that
# release is unavailable, install straight from the repo, and only then fall
# back to a cloned wrapper.
_i_lfimap() {
    pipx_install lfimap && return 0
    if [ "$HAVE_PIPX" = "1" ] && pipx install --force "git+https://github.com/hansmach1ne/LFImap.git" 2>/dev/null; then
        return 0
    fi
    git_script_install lfimap https://github.com/hansmach1ne/LFImap.git lfimap.py
}

# Corsy is a single script with one dependency (requests) and no release of
# any kind -- clone + wrapper is the only install route upstream offers.
_i_corsy() {
    git_script_install corsy https://github.com/s0md3v/Corsy.git corsy.py requests
}

_i_ssrfmap() {
    git_script_install ssrfmap https://github.com/swisskyrepo/SSRFmap.git ssrfmap.py
}

# tplmap has been unmaintained for years, is Python 2 era and is in no
# repository, so installing it would hand you a tool that cannot run.
# SSTImap is the actively maintained Python 3 successor built on tplmap's
# codebase and takes the same -u URL form, so that is what gets installed;
# the SSTI button prefers it and still falls back to tplmap if you already
# have a working copy.
_i_sstimap() {
    git_script_install sstimap https://github.com/vladko312/SSTImap.git sstimap.py
}

# ProjectDiscovery's httpx binary collides in name with an unrelated Python
# "httpx" package, so Kali ships it as "httpx-toolkit" (this app already
# calls it that in commands.py). If installed via `go install`, the binary
# comes out named "httpx" and needs renaming on the way into ~/.local/bin.
_i_httpx_toolkit() {
    apt_install httpx-toolkit && return
    if [ "$HAVE_GO" = "1" ]; then
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest || return 1
        [ -f "$GOBIN/httpx" ] && cp -f "$GOBIN/httpx" "$HOME/.local/bin/httpx-toolkit"
    else
        echo "Go is not installed -- install it first with: sudo apt install -y golang-go"
        return 1
    fi
}

# graphw00f has no apt/pipx package — clone the repo and either let pipx
# install it from git (works if the repo carries packaging metadata) or fall
# back to a plain venv + wrapper script.
_i_graphw00f() {
    if [ "$HAVE_PIPX" = "1" ] && pipx install --force "git+https://github.com/dolevf/graphw00f.git" 2>/dev/null; then
        return 0
    fi
    echo "[*] pipx git install did not work for graphw00f -- falling back to manual clone + wrapper"
    local dir="$TOOLS_DIR/graphw00f"
    if [ ! -d "$dir" ]; then
        git clone --depth 1 https://github.com/dolevf/graphw00f.git "$dir" || return 1
    else
        git -C "$dir" pull --ff-only >/dev/null 2>&1
    fi
    pip3 install --user --break-system-packages -r "$dir/requirements.txt" 2>/dev/null \
        || pip3 install --user -r "$dir/requirements.txt"
    cat > "$HOME/.local/bin/graphw00f" <<EOF
#!/bin/bash
exec python3 "$dir/main.py" "\$@"
EOF
    chmod +x "$HOME/.local/bin/graphw00f"
}

# Not on PyPI under a name pipx can find directly, but the repo installs
# cleanly straight from git.
_i_paramspider() {
    pipx install --force "git+https://github.com/devanshbatham/ParamSpider.git"
}

# ── gf patterns (xss.json, sqli.json, ...) ──────────────────────────────
# gf needs a ~/.gf directory of pattern files — without it, `gf xss` runs
# but matches nothing (silently, not an error), which looks identical to
# "no XSS params found" and wastes a tester's time chasing a phantom result.
setup_gf_patterns() {
    if ! command -v gf >/dev/null 2>&1; then
        return
    fi
    mkdir -p "$HOME/.gf"
    if [ -f "$HOME/.gf/xss.json" ]; then
        report "gf patterns" ok
        return
    fi
    if [ "$CHECK_ONLY" = "1" ]; then
        report "gf patterns" missing "run Install/Repair to fetch them"
        return
    fi
    echo "  [*] gf patterns: missing -- fetching..."
    local tmp
    tmp="$(mktemp -d)"
    if git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$tmp" >/tmp/cb_install_gfpatterns.log 2>&1; then
        cp "$tmp"/*.json "$HOME/.gf/" 2>/dev/null
    fi
    rm -rf "$tmp"
    if [ -f "$HOME/.gf/xss.json" ]; then
        report "gf patterns" fixed
    else
        report "gf patterns" failed "log: /tmp/cb_install_gfpatterns.log"
    fi
}

# ── run ──────────────────────────────────────────────────────────────────

echo "================================================================"
if [ "$CHECK_ONLY" = "1" ]; then
    echo " Command Bridge -- Tool Check (no changes made)"
else
    echo " Command Bridge -- Tool Install / Repair"
fi
echo "================================================================"
echo
[ "$HAVE_GO" = "0" ]   && echo "[i] Go is not installed -- Go-only tools (Gxss, kxss, urldedupe, ...) will be skipped. Install with: sudo apt install -y golang-go"
[ "$HAVE_PIPX" = "0" ] && echo "[i] pipx is not installed -- Python-packaged tools (droopescan, uro, arjun, ...) will be skipped. Install with: sudo apt install -y pipx"
echo

echo "-- Network / recon scanning --"
handle_tool "nmap"        nmap        _i_nmap
handle_tool "rustscan"    rustscan    _i_rustscan    --version
handle_tool "masscan"     masscan     _i_masscan     --help
handle_tool "hping3"      hping3      _i_hping3      --version
handle_tool "ike-scan"    ike-scan    _i_ike_scan
handle_tool "ssh-audit"   ssh-audit   _i_ssh_audit
handle_tool "dnsx"        dnsx        _i_dnsx
handle_tool "theHarvester" theHarvester _i_theharvester
hr

echo "-- Directory / content fuzzing --"
handle_tool "ffuf"        ffuf        _i_ffuf
handle_tool "gobuster"    gobuster    _i_gobuster
handle_tool "feroxbuster" feroxbuster _i_feroxbuster
handle_tool "dirsearch"   dirsearch   _i_dirsearch
handle_tool "wfuzz"       wfuzz       _i_wfuzz
hr

echo "-- Web app / API testing --"
handle_tool "sqlmap"      sqlmap      _i_sqlmap
handle_tool "nuclei"      nuclei      _i_nuclei
handle_tool "whatweb"     whatweb     _i_whatweb
handle_tool "testssl"     testssl     _i_testssl
# Kali ships the binary as testssl.sh and _i_testssl symlinks it to the
# bare name. Coffee Break calls both spellings, so both are declared
# here — a machine where the symlink did not take still gets covered.
handle_tool "testssl.sh" testssl.sh  _i_testssl
handle_tool "arjun"       arjun       _i_arjun
handle_tool "wpscan"      wpscan      _i_wpscan
handle_tool "droopescan"  droopescan  _i_droopescan
handle_tool "graphql-cop" graphql-cop _i_graphql_cop
handle_tool "graphw00f"   graphw00f   _i_graphw00f
handle_tool "nikto"       nikto       _i_nikto       -Version
handle_tool "wafw00f"     wafw00f     _i_wafw00f
handle_tool "corsy"       corsy       _i_corsy
handle_tool "ssrfmap"     ssrfmap     _i_ssrfmap
handle_tool "sstimap"     sstimap     _i_sstimap
handle_tool "lfimap"      lfimap      _i_lfimap
handle_tool "dotdotpwn"   dotdotpwn   _i_dotdotpwn
hr

echo "-- Bug-bounty recon / XSS-hunting chain --"
handle_tool "gau"           gau           _i_gau
handle_tool "waybackurls"   waybackurls   _i_waybackurls
handle_tool "gf"            gf            _i_gf
setup_gf_patterns
handle_tool "uro"           uro           _i_uro
handle_tool "Gxss"          Gxss          _i_Gxss
handle_tool "kxss"          kxss          _i_kxss
handle_tool "dalfox"        dalfox        _i_dalfox        --version
handle_tool "httpx-toolkit" httpx-toolkit _i_httpx_toolkit
handle_tool "katana"        katana        _i_katana
handle_tool "subfinder"     subfinder     _i_subfinder
handle_tool "amass"         amass         _i_amass
handle_tool "ghauri"        ghauri        _i_ghauri
handle_tool "urldedupe"     urldedupe     _i_urldedupe     -h
handle_tool "paramspider"   paramspider   _i_paramspider
handle_tool "hakrawler"     hakrawler     _i_hakrawler
handle_tool "subzy"         subzy         _i_subzy
hr

echo
echo "================================================================"
echo " SUMMARY"
echo "================================================================"
echo "  OK / already working : ${#OK_LIST[@]}"
[ "$CHECK_ONLY" = "0" ] && echo "  Fixed this run        : ${#FIXED_LIST[@]}"
echo "  Missing / broken      : ${#MISSING_LIST[@]}"
[ "$CHECK_ONLY" = "0" ] && echo "  Failed to fix          : ${#FAILED_LIST[@]}"
echo "  Skipped               : ${#SKIPPED_LIST[@]}"
echo
if [ "${#FAILED_LIST[@]}" -gt 0 ]; then
    echo "  Failed: ${FAILED_LIST[*]}"
fi
if [ "${#MISSING_LIST[@]}" -gt 0 ] && [ "$CHECK_ONLY" = "1" ]; then
    echo "  Missing/broken: ${MISSING_LIST[*]}"
    echo "  Run 'Install / Repair Missing Tools' to fix these."
fi
if [ "${#SKIPPED_LIST[@]}" -gt 0 ]; then
    echo "  Skipped: ${SKIPPED_LIST[*]}"
fi

# Anything that needed apt but had nowhere to ask for a password. One command
# beats a failure line per tool, and it can be pasted straight into a terminal.
if [ "${#APT_DEFERRED[@]}" -gt 0 ]; then
    echo
    echo "  ----------------------------------------------------------------"
    echo "  ${#APT_DEFERRED[@]} tool(s) need apt, which cannot ask for your password"
    echo "  from inside the app. Run this once in a terminal, then press"
    echo "  'Check Installed Tools' again:"
    echo
    echo "      sudo apt-get install -y ${APT_DEFERRED[*]}"
    echo
    echo "  (Installing the 'pkexec' package, or giving your user a NOPASSWD"
    echo "  sudo rule for apt-get, lets this button do it for you next time.)"
    echo "  ----------------------------------------------------------------"
fi
echo
echo "[i] Go/pipx-installed binaries are copied into ~/.local/bin so they are"
echo "    found on PATH by every future command this app runs, with no shell"
echo "    restart needed."
echo "================================================================"
