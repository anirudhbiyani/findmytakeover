#!/usr/bin/env python3
"""Fingerprints for third-party SaaS services that are prone to dangling-CNAME
subdomain takeover.

If a CNAME still points at one of these hostnames but the target itself no
longer exists (NXDOMAIN), the service name/slug is typically free for an
attacker to re-register on the SaaS platform, which hands them the subdomain.
This module only maps a target hostname to the service that owns it -- it
makes no network calls. The DNS-resolution check that turns a fingerprint
match into a confirmed finding lives in findmytakeover.py.

Deliberately excludes AWS/GCP/Azure suffixes: those are already classified as
first-party cloud targets in findmytakeover._TARGET_SIGNATURES and are
checked against real inventory rather than fingerprinted.
"""

# (target-hostname suffix, service display name) pairs. identify_service()
# does a case-insensitive substring/suffix match and returns on first hit, so
# order doesn't matter as long as suffixes aren't ambiguous with each other.
_FINGERPRINTS = (
    ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("herokussl.com", "Heroku"),
    ("myshopify.com", "Shopify"),
    ("netlify.app", "Netlify"),
    ("netlifyglobalcdn.com", "Netlify"),
    ("fastly.net", "Fastly"),
    ("zendesk.com", "Zendesk"),
    ("surge.sh", "Surge"),
    ("ghost.io", "Ghost"),
    ("helpscoutdocs.com", "Helpscout"),
    ("helpscout.net", "Helpscout"),
    ("pantheonsite.io", "Pantheon"),
    ("tilda.ws", "Tilda"),
    ("webflow.io", "Webflow"),
    ("proxy-ssl.webflow.com", "Webflow"),
    ("readme.io", "Readme"),
    ("statuspage.io", "Statuspage"),
    ("unbounce.com", "Unbounce"),
    ("unbounceapp.com", "Unbounce"),
    ("wistia.com", "Wistia"),
    ("wistia.net", "Wistia"),
    ("desk.com", "Desk"),
    ("bitbucket.io", "Bitbucket"),
)


def identify_service(value):
    """Return the SaaS service name a DNS target's hostname belongs to, or
    None if it doesn't match any known takeover-prone fingerprint."""
    v = str(value).rstrip(".").lower()
    for suffix, service in _FINGERPRINTS:
        if v == suffix or v.endswith("." + suffix):
            return service
    return None
