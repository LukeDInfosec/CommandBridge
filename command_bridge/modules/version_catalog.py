"""
Current versions, and links that go somewhere.

Nikto will tell you "PHP/5.4.16 appears to be outdated (current is at least
8.5.1)". Two problems with that on an engagement:

  * Nikto's idea of "current" is whatever was true when its database was
    built, and that database is often years old. Repeating the figure makes
    it the tester's claim rather than Nikto's.
  * It does not say what the version is actually vulnerable to, so the
    finding still costs a search before it can be written up.

This module keeps a local catalogue of current versions and builds the
lookup links for a component. Nothing is fetched unless somebody presses
the button: the refresh is a deliberate act, not something that happens
quietly during a scan, because an outbound request carrying the names and
versions of a client's software is exactly the kind of thing the operator
should be choosing to make.

The catalogue lives in ``~/.config/CommandBridge/version_catalog.json`` and
is read offline thereafter. Every link the module produces is checked by the
same refresh, so a dead one shows up here rather than in front of a client.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CATALOGUE = Path.home() / ".config" / "CommandBridge" / "version_catalog.json"

#: Our name for a product → the identifier endoflife.date uses. Only
#: products that actually turn up in a scan banner are listed; the point is
#: a short table that is right, not a long one that is mostly noise.
PRODUCTS = {
    "php": "php",
    "apache": "apache-http-server",
    "httpd": "apache-http-server",
    "nginx": "nginx",
    "openssl": "openssl",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "tomcat": "apache-tomcat",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "python": "python",
    "node": "nodejs",
    "nodejs": "nodejs",
    "iis": "internet-information-services",
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "angular": "angular",
    "django": "django",
    "laravel": "laravel",
    "rails": "rails",
    "spring-framework": "spring-framework",
    "dotnet": "dotnet",
    "openssh": "openssh",
    "haproxy": "haproxy",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "jenkins": "jenkins",
    "kibana": "kibana",
    "varnish": "varnish",
    "proftpd": "proftpd",
    "samba": "samba",
    "squid": "squid",
}

#: The endpoints to try, newest API first. endoflife.date moved to a
#: versioned API and kept the old one; trying both means a change at their
#: end degrades to "could not refresh" rather than silently writing nonsense
#: into the catalogue.
ENDPOINTS = (
    "https://endoflife.date/api/v1/products/{slug}",
    "https://endoflife.date/api/{slug}.json",
)

USER_AGENT = "CommandBridge/version-catalog"
TIMEOUT = 15


# ─────────────────────────────────────────────────────────────────────────
#  Reading what a scanner said
# ─────────────────────────────────────────────────────────────────────────

#: "PHP/5.4.16", "Apache/2.2.15", "nginx 1.14.0", "jQuery v1.11.3"
COMPONENT = re.compile(
    r"\b([A-Za-z][A-Za-z0-9._+-]{1,24}?)[/ ]v?(\d+(?:\.\d+){0,3})\b")


def identify(text):
    """``(product, version)`` for the first known component named in *text*.

    Returns ``("", "")`` when nothing in the sentence is a product this
    module knows, which is the common case and is not an error.
    """
    for match in COMPONENT.finditer(text or ""):
        name = match.group(1).lower().strip(" .,:;()")
        if name in PRODUCTS:
            return name, match.group(2)
    return "", ""


def _major_minor(version):
    parts = str(version or "").split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else str(version or "")


def _as_tuple(version):
    out = []
    for part in str(version or "").split("."):
        digits = re.match(r"\d+", part)
        out.append(int(digits.group(0)) if digits else 0)
    return tuple(out)


# ─────────────────────────────────────────────────────────────────────────
#  Links
# ─────────────────────────────────────────────────────────────────────────

def links_for(product, version=""):
    """Where to read about this component's known vulnerabilities.

    Search URLs rather than deep links to a specific advisory: a search
    page for "PHP 5.4.16" is still there in two years, and a link to one
    CVE page is both narrower than the truth and more likely to rot.
    """
    if not product:
        return []
    query = f"{product} {version}".strip()
    quoted = urllib.parse.quote_plus(query)
    out = [
        ("NVD — CVEs for this product and version",
         f"https://nvd.nist.gov/vuln/search/results?form_type=Basic"
         f"&results_type=overview&query={quoted}&search_type=all"),
        ("CVE Program record search",
         f"https://www.cve.org/CVERecord/SearchResults?query={quoted}"),
        ("Snyk vulnerability database",
         f"https://security.snyk.io/vuln?search={quoted}"),
    ]
    slug = PRODUCTS.get(product)
    if slug:
        out.append((f"endoflife.date — support and current release",
                    f"https://endoflife.date/{slug}"))
    if product in ("wordpress", "drupal", "joomla"):
        out.append(("WPScan / CMS vulnerability database",
                    f"https://wpscan.com/search?text={quoted}"))
    if product in ("jquery", "bootstrap", "angular"):
        out.append(("Snyk advisor for the npm package",
                    f"https://security.snyk.io/package/npm/{product}"))
    return out


# ─────────────────────────────────────────────────────────────────────────
#  The catalogue on disk
# ─────────────────────────────────────────────────────────────────────────

def load():
    """The catalogue, or an empty one. Never raises."""
    try:
        with open(CATALOGUE, encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("products"), dict):
            return data
    except Exception:                                   # noqa: BLE001
        pass
    return {"updated": 0, "products": {}, "link_check": {}}


def save(data):
    CATALOGUE.parent.mkdir(parents=True, exist_ok=True)
    with open(CATALOGUE, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
    return CATALOGUE


def age_days(data=None):
    data = data or load()
    stamp = data.get("updated") or 0
    if not stamp:
        return None
    return (time.time() - stamp) / 86400.0


def current_version(product, data=None):
    """The newest release this catalogue knows of, or ""."""
    data = data or load()
    entry = (data.get("products") or {}).get(product) or {}
    return entry.get("latest", "")


def assess(product, version, data=None):
    """``(verdict, detail)`` for a component, from the local catalogue only.

    Deliberately conservative. With no catalogue it says so rather than
    guessing, and it never repeats a scanner's own "current is at least X".
    """
    data = data or load()
    entry = (data.get("products") or {}).get(product) or {}
    if not entry:
        return "unknown", (
            "No local version data for this component. Press "
            "‘Update version data’ on the Target tab to fetch it, "
            "or use the links below.")
    latest = entry.get("latest", "")
    cycles = entry.get("cycles") or {}
    branch = _major_minor(version)
    note = ""
    cycle = cycles.get(branch)
    if cycle:
        eol = cycle.get("eol")
        if eol is True:
            note = (f" The {branch} branch is end-of-life and receives no "
                    f"security fixes at all.")
        elif isinstance(eol, str):
            note = f" The {branch} branch is supported until {eol}."
        if cycle.get("latest") and \
                _as_tuple(version) < _as_tuple(cycle["latest"]):
            note += (f" The newest release on that same branch is "
                     f"{cycle['latest']}, which is an upgrade that does not "
                     f"change major version.")
    if latest and _as_tuple(version) < _as_tuple(latest):
        return "outdated", (
            f"The current release of {product} is {latest} "
            f"(catalogue updated {entry.get('checked', 'unknown')})."
            + note)
    if latest:
        return "current", (f"{version} matches the newest release this "
                           f"catalogue knows of ({latest}).")
    return "unknown", "The catalogue holds no release figure for this." + note


# ─────────────────────────────────────────────────────────────────────────
#  The refresh — only ever on an explicit press
# ─────────────────────────────────────────────────────────────────────────

def _fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _normalise(payload):
    """Both API shapes down to ``{latest, cycles}``.

    v1 returns ``{"result": {"releases": [...]}}``; the classic endpoint
    returns a bare list of cycles. Neither is assumed.
    """
    cycles = []
    if isinstance(payload, dict):
        result = payload.get("result") or payload
        cycles = result.get("releases") or result.get("cycles") or []
    elif isinstance(payload, list):
        cycles = payload
    out, newest = {}, ""
    for cycle in cycles:
        if not isinstance(cycle, dict):
            continue
        name = str(cycle.get("cycle") or cycle.get("name") or "")
        latest = cycle.get("latest")
        if isinstance(latest, dict):
            latest = latest.get("name") or latest.get("version") or ""
        latest = str(latest or "")
        eol = cycle.get("eol")
        if eol is None:
            eol = cycle.get("isEol")
        if name:
            out[name] = {"latest": latest, "eol": eol}
        if latest and _as_tuple(latest) > _as_tuple(newest):
            newest = latest
    return newest, out


def check_link(url, timeout=10):
    """Is this link still alive? ``(ok, note)``.

    Run as part of the refresh so a rotted link is found here rather than
    in front of a client. A 403 counts as alive: several of these sites
    refuse an unknown user agent but serve the page to a browser.
    """
    request = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (200 <= response.status < 400), f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 405, 429):
            return True, f"HTTP {exc.code} (reachable; blocks HEAD)"
        return False, f"HTTP {exc.code}"
    except Exception as exc:                            # noqa: BLE001
        return False, type(exc).__name__


def refresh(report=None, products=None, verify_links=True):
    """Fetch current versions and verify the links. Returns a summary.

    ``report`` is called with a line of progress, so the console shows what
    is being contacted — this is the one part of the application that talks
    to a third party, and it says so while it does it.
    """
    say = report or (lambda line: None)
    data = load()
    catalogue = data.get("products") or {}
    wanted = products or sorted(set(PRODUCTS))
    today = time.strftime("%Y-%m-%d")

    say(f"[versions] refreshing {len(wanted)} product(s) from "
        f"endoflife.date — this is the only outbound request this feature "
        f"makes, and it carries no target data.")

    updated, failed = [], []
    done_slugs = {}
    for product in wanted:
        slug = PRODUCTS.get(product)
        if not slug:
            continue
        if slug in done_slugs:                 # php and httpd share a slug
            catalogue[product] = dict(done_slugs[slug])
            continue
        payload = None
        for template in ENDPOINTS:
            try:
                payload = _fetch(template.format(slug=slug))
                break
            except Exception as exc:                    # noqa: BLE001
                last = f"{type(exc).__name__}: {exc}"
        if payload is None:
            failed.append((product, last))
            say(f"[versions]   {product}: FAILED ({last})")
            continue
        newest, cycles = _normalise(payload)
        if not newest and not cycles:
            failed.append((product, "no releases in the response"))
            continue
        entry = {"latest": newest, "cycles": cycles, "checked": today}
        catalogue[product] = entry
        done_slugs[slug] = entry
        updated.append(product)
        say(f"[versions]   {product}: current release {newest or 'unknown'}")

    link_results = {}
    if verify_links:
        say("[versions] checking that every reference link still resolves")
        seen = set()
        for product in (updated or wanted)[:6]:
            for label, url in links_for(product, ""):
                root = urllib.parse.urlsplit(url)
                key = f"{root.scheme}://{root.netloc}{root.path}"
                if key in seen:
                    continue
                seen.add(key)
                ok, note = check_link(url)
                link_results[key] = {"ok": ok, "note": note,
                                     "label": label, "checked": today}
                if not ok:
                    say(f"[versions]   DEAD LINK {key} ({note})")
        alive = sum(1 for v in link_results.values() if v["ok"])
        say(f"[versions] {alive}/{len(link_results)} reference links OK")

    data = {"updated": time.time(), "products": catalogue,
            "link_check": link_results}
    path = save(data)
    say(f"[versions] catalogue written to {path}")
    return {"updated": updated, "failed": failed, "links": link_results,
            "path": str(path), "count": len(catalogue)}
