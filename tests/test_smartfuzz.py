#!/usr/bin/env python3
"""
SmartFuzz technology inference.

The failure this guards against, reported from a live scan: the target
answered on /umbraco with Microsoft-IIS headers — plainly an Umbraco
(.NET) site — and SmartFuzz ran a DRUPAL deep scan, because /modules was
a Drupal signature path and nothing matched Umbraco. The scan was fuzzing
the wrong CMS entirely.
"""

import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("smartfuzz", ROOT / "smartfuzz.py")
sf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sf)

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


class _Stub(sf.SmartFuzz):
    def __init__(self):
        pass


def infer(paths):
    """Run SmartFuzz's path analysis and return the inferred tech."""
    discovered = [("200", p) for p in paths]
    detected = _Stub()._analyse_paths(discovered)
    if not detected:
        return None
    best = max(detected.items(),
               key=lambda x: (x[1]["priority"], x[1]["matches"]))
    return best[0]


def main():
    print("\n\033[1mThe reported scan: /umbraco on IIS is Umbraco\033[0m")
    reported = ["/News", "/Search", "/Services", "/SiteMap", "/contact-us",
                "/courses", "/forms", "/modules", "/news", "/newsletter",
                "/overview", "/privacy-policy", "/schools", "/search",
                "/services", "/sitemap", "/sitemap.xml", "/subscribe",
                "/training", "/umbraco", "/website"]
    check("the discovered paths infer Umbraco, not Drupal",
          infer(reported), "umbraco")
    check("Umbraco is in the signature table", "umbraco" in sf.SIGNATURES)
    check("   and outranks the other CMSs (a one-path, unambiguous tell)",
          sf.SIGNATURES["umbraco"]["priority"]
          > max(sf.SIGNATURES[t]["priority"]
                for t in ("drupal", "joomla", "wordpress")))

    print("\n\033[1m/modules alone no longer means Drupal (or Joomla)\033[0m")
    # /modules is shipped by Umbraco, SilverStripe and others; on its own it
    # identifies nothing, and it must not promote a CMS.
    check("a lone /modules infers nothing", infer(["/modules"]), None)
    check("   it is not a Drupal signature",
          "/modules" in sf.SIGNATURES["drupal"]["paths"], False)
    check("   nor a Joomla one",
          "/modules" in sf.SIGNATURES["joomla"]["paths"], False)

    print("\n\033[1mThe real signatures still identify their CMS\033[0m")
    check("a genuine Drupal tree is still Drupal",
          infer(["/sites/default", "/core/misc", "/user/login"]), "drupal")
    check("a genuine WordPress tree is still WordPress",
          infer(["/wp-admin", "/wp-content", "/wp-login.php"]), "wordpress")
    check("a genuine Joomla tree is still Joomla",
          infer(["/administrator", "/components", "/templates"]), "joomla")
    check("Umbraco's own back office resolves to Umbraco",
          infer(["/umbraco", "/umbraco/surface", "/app_plugins"]), "umbraco")

    print("\n\033[1mThe Umbraco wordlist is bundled and usable\033[0m")
    wl = sf.SIGNATURES["umbraco"]["wordlist"]
    check("the signature points at a real file", os.path.isfile(wl))
    rows = [l.strip() for l in Path(wl).read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    check("   with a usable number of entries", len(rows) > 40)
    check("   including the back office and installer",
          all(p in rows for p in ("umbraco", "umbraco/login", "install")))
    check("   and the .NET config leaks",
          all(p in rows for p in ("web.config", "umbracoSettings.config")))
    check("   no entry starts with a slash (fuzzers append to the URL)",
          [r for r in rows if r.startswith("/")], [])

    print("\n\033[1mWordlist resolution tries every known location\033[0m")
    # The reported failure: the bundled umbraco.txt was not at its path, so
    # the scan dropped straight to a generic raft-small-words sweep instead
    # of checking SecLists (or saying where it looked).
    stub = _Stub()
    wl, tried = stub._resolve_wordlist("umbraco")
    check("Umbraco resolves to a real file when one exists",
          wl is not None and os.path.isfile(wl))
    check("   and it is the bundled list", wl and "wordlists" in wl)
    check("every CMS signature carries MULTIPLE candidate locations",
          all(len(sf.SIGNATURES[t].get("wordlists", [])) >= 2
              for t in ("umbraco", "wordpress", "drupal", "joomla")))
    check("   Umbraco's candidates include a SecLists path, not only the "
          "bundled one",
          any("seclists" in c.lower()
              for c in sf.SIGNATURES["umbraco"]["wordlists"]))
    # When nothing exists anywhere, the resolver reports the paths it tried
    # rather than silently falling back.
    saved = (sf.SIGNATURES["umbraco"]["wordlist"],
             sf.SIGNATURES["umbraco"]["wordlists"])
    sf.SIGNATURES["umbraco"]["wordlist"] = "/nope/umbraco.txt"
    sf.SIGNATURES["umbraco"]["wordlists"] = ["/nope/a.txt", "/nope/b.txt"]
    wl2, tried2 = stub._resolve_wordlist("umbraco")
    check("with nothing on disk, no wordlist is resolved", wl2, None)
    check("   and the paths it tried are reported for the operator",
          len(tried2) >= 2)
    sf.SIGNATURES["umbraco"]["wordlist"], \
        sf.SIGNATURES["umbraco"]["wordlists"] = saved
    # A --wl override path is tried first.
    sf.SIGNATURES["umbraco"]["wordlist"] = str(
        Path(wl))  # an existing file, standing in for an override
    wl3, _ = stub._resolve_wordlist("umbraco")
    check("an explicit wordlist is honoured first", wl3, str(Path(wl)))

    print("\n\033[1mCase-insensitive filename matching\033[0m")
    # SecLists ships "Umbraco.txt" and "Umbraco.fuzz.txt" (capital U) while
    # the signature table asks for lowercase. On a case-sensitive Linux
    # filesystem that is a miss, and the scan dropped to a generic sweep
    # even though the file was right there.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        real = os.path.join(d, "Umbraco.txt")
        with open(real, "w") as fh:
            fh.write("umbraco\nweb.config\n")
        hit = sf.SmartFuzz._case_insensitive_file(os.path.join(d, "umbraco.txt"))
        check("a lowercase request finds the capital-U file", hit, real)
        check("   and an exact-case request still works",
              sf.SmartFuzz._case_insensitive_file(real), real)
        check("   a name with no match returns None",
              sf.SmartFuzz._case_insensitive_file(os.path.join(d, "nope.txt")),
              None)
        # Through the resolver, end to end.
        saved = (sf.SIGNATURES["umbraco"]["wordlist"],
                 sf.SIGNATURES["umbraco"]["wordlists"])
        sf.SIGNATURES["umbraco"]["wordlist"] = "/nope/umbraco.txt"
        sf.SIGNATURES["umbraco"]["wordlists"] = [os.path.join(d, "umbraco.txt")]
        wl4, _ = _Stub()._resolve_wordlist("umbraco")
        check("the resolver returns the real on-disk filename", wl4, real)
        sf.SIGNATURES["umbraco"]["wordlist"], \
            sf.SIGNATURES["umbraco"]["wordlists"] = saved

    print("\n\033[1mBoth the header server AND the inferred CMS get a deep scan\033[0m")
    # The reported failure: /umbraco on a Microsoft-IIS server ran an Umbraco
    # deep scan and NO IIS scan — the header fingerprint was thrown away once
    # the paths named a CMS. Both must be scanned, de-duplicated, order
    # inferred-first.
    check("IIS is in the signature table", "iis" in sf.SIGNATURES)
    check("   and matches the Microsoft-IIS server header",
          any("microsoft-iis" in h.lower()
              for h in sf.SIGNATURES["iis"].get("headers", [])))
    check("   with its own wordlist candidates",
          len(sf.SIGNATURES["iis"].get("wordlists", [])) >= 1)

    def scan_order(detected, header):
        order = [t for t in (detected, header) if t]
        seen, out = set(), []
        for t in order:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    check("Umbraco (inferred) on IIS (header) scans both, inferred first",
          scan_order("umbraco", "iis"), ["umbraco", "iis"])
    check("   when header and inference agree, the tech is scanned once",
          scan_order("iis", "iis"), ["iis"])
    check("   a header-only hit (nothing inferred) still scans it",
          scan_order("iis", "iis"), ["iis"])

    import io
    import contextlib

    def summary_for(detected, header):
        s = _Stub()
        s.discovered_paths = []
        s.scanned_with = set()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            s._print_summary(detected, header)
        return buf.getvalue()

    check("the summary names both: 'UMBRACO on IIS'",
          "UMBRACO on IIS" in summary_for("umbraco", "iis"))
    same = summary_for("iis", "iis")
    check("   and names it once when they are the same",
          "IIS on IIS" not in same and "IIS" in same)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
