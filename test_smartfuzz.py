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

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
