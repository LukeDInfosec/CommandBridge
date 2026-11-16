"""
Every outbound request this application makes, on the record.

A pentest tool runs on an engagement where the client has asked what it
talks to. "Nothing but your target" is an assertion; this module is how
it is demonstrated. Two mechanisms, both operator-controlled from the
Target tab:

  * **Proxy everything.** One setting sends this application's own HTTP
    and every tool it shells out to through a proxy of the operator's
    choosing — Burp, ZAP, mitmproxy. If a request is not in the proxy's
    history, it was not made; if one is there that the operator did not
    expect, it is visible with its full body.

  * **Log everything.** An append-only JSONL file recording every
    outbound request: when, which component, the method, the URL, and
    whether the host was in the engagement's scope. Readable offline,
    diffable, and attachable to a report.

Two design rules, because the point of this file is that it can be
trusted:

  1. It records what was ATTEMPTED, at the point of attempt, before any
     response. A log that only recorded successes would hide exactly
     the request someone would care about.
  2. It records the URL and never the body. The log is a record of where
     traffic went, and a tester's requests contain credentials, session
     tokens and client data. The proxy is the right place to inspect
     content, because that is the operator's own tooling and their own
     disk.

Nothing here is on by default: an application that silently routed a
tester's traffic through a proxy would be its own kind of surprise.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

#: Hosts this application is allowed to contact for its own purposes,
#: beyond the engagement's target. Deliberately tiny and explicit:
#: anything on this list is a decision someone can argue with, which is
#: the point. A host NOT on it and not in scope is flagged in the log.
#:
#: These are reached only by features the operator starts by hand:
#: certificate transparency lookups (crt.sh), the update check and the
#: tool installers, which fetch from the distributions' own hosts.
KNOWN_HOSTS = {
    "crt.sh": "certificate transparency search (Recon tab)",
    "api.github.com": "update check and tool downloads",
    "github.com": "update check and tool downloads",
    "objects.githubusercontent.com": "tool downloads from GitHub releases",
    "raw.githubusercontent.com": "wordlist and template downloads",
    "codeload.github.com": "tool source downloads",
    "pypi.org": "Python package installs",
    "files.pythonhosted.org": "Python package installs",
    "proxy.golang.org": "Go tool installs",
    "sum.golang.org": "Go tool installs",
    "cve.circl.lu": "CVE lookups",
    "services.nvd.nist.gov": "CVE lookups",
}

#: What this application never contacts. There is no telemetry endpoint,
#: no crash reporter and no licence server, so there is nothing to list
#: here — and a log that stays empty of unexplained hosts is the
#: evidence for that, not this comment.
TELEMETRY_HOSTS = frozenset()


class Egress:
    """The settings and the log. One instance, shared."""

    def __init__(self):
        self._lock = threading.Lock()
        self.proxy_enabled = False
        self.proxy_url = ""
        self.log_enabled = False
        self.log_path = None
        #: Hosts in the engagement's scope, lowercased, set by the
        #: Target tab when a target is set.
        self.scope = set()
        #: Counters, for the summary the UI shows without reading the
        #: file back. {host: {"count": n, "in_scope": bool, "tools": set}}
        self.hosts = {}
        self.recorded = 0
        self.unexpected = 0
        self.verify_tls = True

    # ── settings ─────────────────────────────────────────────────────
    def configure(self, proxy_url=None, proxy_enabled=None, log_enabled=None,
                  log_path=None, verify_tls=None):
        # Every argument defaults to None and means "leave this as it
        # is". proxy_url used to default to "", so configure(
        # proxy_enabled=True) silently cleared the address it was being
        # switched on for.
        with self._lock:
            if proxy_url is not None:
                self.proxy_url = normalise_proxy(proxy_url)
            if proxy_enabled is not None:
                self.proxy_enabled = bool(proxy_enabled)
            if log_enabled is not None:
                self.log_enabled = bool(log_enabled)
            if log_path is not None:
                self.log_path = Path(log_path) if log_path else None
            if verify_tls is not None:
                self.verify_tls = bool(verify_tls)

    def set_scope(self, hosts):
        with self._lock:
            self.scope = {str(h).strip().lower() for h in (hosts or []) if h}

    @property
    def active(self):
        """Is the proxy in use? (Configured AND switched on.)"""
        return bool(self.proxy_enabled and self.proxy_url)

    def proxies(self):
        """A requests-style proxies dict, or {} when not proxying."""
        if not self.active:
            return {}
        return {"http": self.proxy_url, "https": self.proxy_url}

    def env_pairs(self):
        """Environment for child processes, so shelled-out tools proxy too.

        Most tools honour HTTP_PROXY/HTTPS_PROXY. Those that have their
        own flag get it from :func:`proxy_arguments`; both are applied,
        because a tool that honours neither would otherwise look proxied
        and not be.
        """
        if not self.active:
            return {}
        return {
            "HTTP_PROXY": self.proxy_url, "http_proxy": self.proxy_url,
            "HTTPS_PROXY": self.proxy_url, "https_proxy": self.proxy_url,
            "ALL_PROXY": self.proxy_url, "all_proxy": self.proxy_url,
        }

    # ── the log ──────────────────────────────────────────────────────
    def record(self, method, url, component="", note="", attempted=True):
        """Record one outbound request, BEFORE it is sent.

        The URL is recorded; the body never is. Returns the host.
        """
        host = host_of(url)
        in_scope = self.in_scope(host)
        known = host in KNOWN_HOSTS
        with self._lock:
            entry = self.hosts.setdefault(
                host, {"count": 0, "in_scope": in_scope, "known": known,
                       "components": set()})
            entry["count"] += 1
            if component:
                entry["components"].add(component)
            self.recorded += 1
            unexpected = not in_scope and not known
            if unexpected:
                self.unexpected += 1
            should_write = self.log_enabled and self.log_path
            path = self.log_path
        if should_write:
            self._append(path, {
                "at": round(time.time(), 3),
                "iso": time.strftime("%Y-%m-%dT%H:%M:%S",
                                     time.localtime()),
                "component": component or "unknown",
                "method": str(method or "").upper(),
                "url": redact_url(url),
                "host": host,
                "in_scope": in_scope,
                "known_host": known,
                "expected": in_scope or known,
                "proxied": self.active,
                "attempted": bool(attempted),
                "note": note,
            })
        return host

    def record_command(self, command, component="command"):
        """Record a shell command this application is about to run.

        A tool's own requests appear in the proxy, not here — this
        application cannot see inside nuclei. What it can record, and
        what matters for the question being asked, is the exact command
        line it launched and whether the proxy settings were handed to
        it.
        """
        with self._lock:
            should_write = self.log_enabled and self.log_path
            path = self.log_path
            proxied = self.active
            proxy = self.proxy_url
        if not should_write:
            return
        self._append(path, {
            "at": round(time.time(), 3),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "component": component,
            "kind": "command",
            "command": str(command or "")[:2000],
            "proxied": proxied,
            "proxy": proxy if proxied else "",
            "note": "the tool's own requests appear in the proxy, "
                    "not in this log",
        })

    def _append(self, path, entry):
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except Exception:                                   # noqa: BLE001
            # A failure to log is never allowed to break a scan, but it
            # must not be silent either — the UI reads log_errors.
            self.log_errors = getattr(self, "log_errors", 0) + 1

    def in_scope(self, host):
        host = str(host or "").lower()
        if not host:
            return False
        return any(host == allowed or host.endswith("." + allowed)
                   for allowed in self.scope)

    # ── what the UI shows ────────────────────────────────────────────
    def summary(self):
        """``(lines, unexpected)`` — every host contacted this session."""
        with self._lock:
            rows = sorted(self.hosts.items(),
                          key=lambda item: -item[1]["count"])
            total, unexpected = self.recorded, self.unexpected
        lines = []
        for host, entry in rows:
            if entry["in_scope"]:
                why = "in scope"
            elif entry["known"]:
                why = KNOWN_HOSTS.get(host, "known host")
            else:
                why = "NOT IN SCOPE AND NOT EXPECTED"
            components = ", ".join(sorted(entry["components"])) or "unknown"
            lines.append(f"{entry['count']:6}  {host}  —  {why}  "
                         f"[{components}]")
        return lines, unexpected, total

    def reset(self):
        with self._lock:
            self.hosts = {}
            self.recorded = 0
            self.unexpected = 0


#: The one instance. Imported, not constructed.
STATE = Egress()


def normalise_proxy(value):
    """"127.0.0.1:8080" → "http://127.0.0.1:8080"."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    return text.rstrip("/")


def host_of(url):
    try:
        parsed = urlparse(str(url or ""))
        return (parsed.hostname or "").lower()
    except Exception:                                       # noqa: BLE001
        return ""


#: Query parameters whose VALUES are not written to the log. The log
#: exists to show where traffic went; a token in a URL would make the
#: log itself a place credentials accumulate.
SENSITIVE_PARAMS = ("token", "key", "secret", "password", "passwd", "pwd",
                    "auth", "session", "sig", "signature", "apikey",
                    "api_key", "access_token", "id_token")


def redact_url(url):
    """The URL, with credential-shaped parameter values removed."""
    text = str(url or "")
    if "?" not in text:
        return text[:2000]
    base, _, query = text.partition("?")
    parts = []
    for pair in query.split("&"):
        name, sep, value = pair.partition("=")
        if sep and value and any(token in name.lower()
                                 for token in SENSITIVE_PARAMS):
            parts.append(f"{name}=<redacted>")
        else:
            parts.append(pair)
    return (base + "?" + "&".join(parts))[:2000]


def default_log_path(output_dir=None):
    base = Path(output_dir) if output_dir else Path.cwd()
    stamp = time.strftime("%Y%m%d_%H%M%S")
    return base / f"command_bridge_egress_{stamp}.jsonl"


# ─────────────────────────────────────────────────────────────────────
#  Catching the application's own requests
# ─────────────────────────────────────────────────────────────────────
#
# Rather than ask every module to remember to log and to proxy — which
# is a promise that holds until someone adds a module — the wrapper goes
# on requests.Session.request and urllib.request.urlopen, which is where
# all of it ends up. One place to read, one place to audit, and a new
# feature is covered the day it is written.

_installed = False


def install():
    """Wrap the HTTP libraries so nothing bypasses the log or the proxy."""
    global _installed
    if _installed:
        return True
    try:
        import requests
    except Exception:                                       # noqa: BLE001
        return False

    original_request = requests.Session.request

    def request(self, method, url, **kwargs):
        STATE.record(method, url, component=_component_for(self))
        if STATE.active and not kwargs.get("proxies"):
            kwargs["proxies"] = STATE.proxies()
            # A proxy intercepting TLS presents its own certificate.
            # Verification is left as the caller set it unless the
            # operator asked for it to be relaxed for the proxy.
            if not STATE.verify_tls:
                kwargs.setdefault("verify", False)
        return original_request(self, method, url, **kwargs)

    requests.Session.request = request

    try:
        import urllib.request as urllib_request

        original_urlopen = urllib_request.urlopen

        def urlopen(url, *args, **kwargs):
            target = getattr(url, "full_url", url)
            method = getattr(url, "method", "GET") or "GET"
            STATE.record(method, target, component="urllib")
            if STATE.active:
                handler = urllib_request.ProxyHandler(STATE.proxies())
                opener = urllib_request.build_opener(handler)
                return opener.open(url, *args, **kwargs)
            return original_urlopen(url, *args, **kwargs)

        urllib_request.urlopen = urlopen
    except Exception:                                       # noqa: BLE001
        pass

    _installed = True
    return True


def _component_for(session):
    """A name for whichever part of the application made the request."""
    return getattr(session, "cb_component", "") or "application"


def apply_to_environment(env=None):
    """Put the proxy settings into an environment mapping, in place."""
    target = env if env is not None else os.environ
    pairs = STATE.env_pairs()
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                 "ALL_PROXY", "all_proxy"):
        target.pop(name, None)
    for name, value in pairs.items():
        target[name] = value
    return target


#: Per-tool proxy flags, for tools that ignore the environment. The
#: value is formatted with the proxy URL. A tool missing from here gets
#: the environment variables and nothing else, which is not a silent
#: failure: the log records whether a flag was added.
PROXY_FLAGS = {
    "nuclei": "-proxy {proxy}",
    "httpx": "-proxy {proxy}",
    "katana": "-proxy {proxy}",
    "ffuf": "-x {proxy}",
    "gobuster": "--proxy {proxy}",
    "dirsearch": "--proxy={proxy}",
    "sqlmap": "--proxy={proxy}",
    "wpscan": "--proxy {proxy}",
    "nikto": "-useproxy {proxy}",
    "testssl": "--proxy {host_port}",
    "testssl.sh": "--proxy {host_port}",
    "curl": "-x {proxy}",
    "graphw00f": "-p {proxy}",
}


def proxy_arguments(tool):
    """The flag this tool needs to use the proxy, or "".

    Empty when no proxy is configured, or when the tool is not one of
    the ones with a flag of its own — those get the environment.
    """
    if not STATE.active:
        return ""
    template = PROXY_FLAGS.get(str(tool or "").strip().lower())
    if not template:
        return ""
    parsed = urlparse(STATE.proxy_url)
    host_port = parsed.netloc or STATE.proxy_url
    return template.format(proxy=STATE.proxy_url, host_port=host_port)


#: Tools that CANNOT be routed through an HTTP proxy, because they do not
#: speak HTTP over one: nmap and masscan open raw sockets, the rest make
#: non-HTTP connections. During a proxied run these produce no traffic in
#: Burp — which is correct, not suspicious, and the honest thing is to say
#: so out loud rather than leave an observer wondering why the first two
#: minutes of a Coffee Break run are silent in the proxy.
UNPROXYABLE_TOOLS = {
    "nmap": "raw TCP/IP packets, not HTTP — watch it in Wireshark or tcpdump",
    "masscan": "raw packets, not HTTP",
    "nc": "a raw socket, not HTTP",
    "ncat": "a raw socket, not HTTP",
    "socat": "a raw socket, not HTTP",
    "ping": "ICMP, not HTTP",
    "traceroute": "ICMP/UDP, not HTTP",
    "dig": "DNS, not HTTP",
    "nslookup": "DNS, not HTTP",
    "host": "DNS, not HTTP",
    "snmpwalk": "SNMP, not HTTP",
    "smbclient": "SMB, not HTTP",
    "enum4linux": "SMB/RPC, not HTTP",
    "sslscan": "a raw TLS handshake, not HTTP — its traffic is to the "
               "target directly",
}


def proxy_note(command):
    """A one-line note when a command's tool cannot use the proxy, else "".

    Only meaningful while proxying is on. Lets the runner say, in the
    console and the log, exactly why a given stage will not appear in the
    proxy — so a live audience sees the gap explained, not hidden.
    """
    if not STATE.active:
        return ""
    text = str(command or "").strip()
    if not text:
        return ""
    # The first real token that is not an env assignment or a shell builtin.
    for token in text.split():
        if "=" in token and not token.startswith("-"):
            continue
        if token in ("sudo", "stdbuf", "yes", "if", "then", "command",
                     "-oL", "-eL"):
            continue
        tool = Path(token).name
        reason = UNPROXYABLE_TOOLS.get(tool)
        if reason:
            return (f"{tool} does not go through the proxy — it uses "
                    f"{reason}. This stage will not appear in Burp/ZAP; "
                    f"that is expected.")
        break
    return ""


def proxy_command(command):
    """Add the proxy flag to a command line, if its tool has one.

    Only ever adds a flag the tool does not already carry: an operator
    who has written their own --proxy into a command has said what they
    want, and a second one would break the command.
    """
    text = str(command or "")
    if not STATE.active or not text.strip():
        return text
    first = text.strip().split()[0]
    tool = Path(first).name
    flag = proxy_arguments(tool)
    if not flag:
        return text
    marker = flag.split()[0].split("=")[0]
    if marker in text:
        return text
    parts = text.split(None, 1)
    return f"{parts[0]} {flag}" + (f" {parts[1]}" if len(parts) > 1 else "")
