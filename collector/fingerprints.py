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

# (target-hostname suffix, service display name) pairs, synced with the
# services can-i-take-over-xyz (github.com/EdOverflow/can-i-take-over-xyz)
# lists as "Vulnerable" or "Edge case". Providers it marks "Not vulnerable"
# (Fastly, Zendesk, Statuspage, Unbounce, Desk) verify domain ownership, so a
# stale CNAME to them is left as an unclassified third-party target instead of
# being called claimable. Matched at DNS label boundaries; first hit wins.
_FINGERPRINTS = (
    ("github.io", "GitHub Pages"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("herokussl.com", "Heroku"),
    ("myshopify.com", "Shopify"),
    ("netlify.app", "Netlify"),
    ("netlifyglobalcdn.com", "Netlify"),
    ("surge.sh", "Surge"),
    ("ghost.io", "Ghost"),
    ("helpscoutdocs.com", "Helpscout"),
    ("helpscout.net", "Helpscout"),
    ("pantheonsite.io", "Pantheon"),
    ("tilda.ws", "Tilda"),
    ("webflow.io", "Webflow"),
    ("proxy-ssl.webflow.com", "Webflow"),
    ("readme.io", "Readme"),
    ("wistia.com", "Wistia"),
    ("wistia.net", "Wistia"),
    ("bitbucket.io", "Bitbucket"),
    ("agilecrm.com", "Agile CRM"),
    ("airee.ru", "Airee"),
    ("animaapp.io", "Anima"),
    ("trydiscourse.com", "Discourse"),
    ("furyns.com", "Gemfury"),
    ("hatenablog.com", "HatenaBlog"),
    ("helpjuice.com", "Help Juice"),
    ("helprace.com", "Helprace"),
    ("youtrack.cloud", "JetBrains YouTrack"),
    ("launchrock.com", "LaunchRock"),
    ("ngrok.io", "Ngrok"),
    ("s.strikinglydns.com", "Strikingly"),
    ("surveysparrow.com", "SurveySparrow"),
    ("read.uberflip.com", "Uberflip"),
    ("stats.uptimerobot.com", "Uptimerobot"),
    ("wordpress.com", "WordPress.com"),
    ("worksites.net", "Worksites"),
)

# Regex matched against the body the provider serves for a hostname nobody
# has claimed (from can-i-take-over-xyz). Used only by --verify-http. Services
# without one are confirmed by NXDOMAIN or not at all.
_HTTP_FINGERPRINTS = {
    "GitHub Pages": r"There isn't a GitHub Pages site here\.",
    "Heroku": r"No such app",
    "Shopify": r"Sorry, this shop is currently unavailable\.",
    "Netlify": r"Not Found - Request ID:",
    "Surge": r"project not found",
    "Ghost": r"Site unavailable\.|Failed to resolve DNS path for this host",
    "Helpscout": r"No settings were found for this company:",
    "Pantheon": r"404 error unknown site!",
    "Tilda": r"Please renew your subscription",
    "Webflow": r"The page you are looking for doesn't exist or has been moved",
    "Readme": r"The creators of this project are still working on making everything perfect!",
    "Bitbucket": r"Repository not found",
    "Agile CRM": r"Sorry, this page is no longer available\.",
    "Airee": r"Ошибка 402\. Сервис Айри\.рф не оплачен",
    "Anima": r"The page you were looking for does not exist\.",
    "Gemfury": r"404: This page could not be found\.",
    "HatenaBlog": r"404 Blog is not found",
    "Help Juice": r"We could not find what you're looking for\.",
    "JetBrains YouTrack": r"is not a registered InCloud YouTrack",
    "Ngrok": r"Tunnel .*\.ngrok\.io not found",
    "Strikingly": r"PAGE NOT FOUND\.",
    "SurveySparrow": r"Account not found\.",
    "Uberflip": r"The URL you've accessed does not provide a hub\.",
    "Uptimerobot": r"page not found",
    "WordPress.com": r"Do you want to register .*\.wordpress\.com\?",
    "Worksites": r"Hello! Sorry, but the website you(?:&rsquo;|’|')re looking for doesn(?:&rsquo;|’|')t exist\.",
}


def identify_service(value):
    """Return the SaaS service name a DNS target's hostname belongs to, or
    None if it doesn't match any known takeover-prone fingerprint."""
    v = str(value).rstrip(".").lower()
    for suffix, service in _FINGERPRINTS:
        if v == suffix or v.endswith("." + suffix):
            return service
    return None


def http_fingerprint(service):
    """Regex for the page `service` serves on an unclaimed hostname, or None."""
    return _HTTP_FINGERPRINTS.get(service)
