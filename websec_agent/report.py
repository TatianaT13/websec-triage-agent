"""Deterministic report + IOC bundle generation, built directly from the
heuristics (no LLM call) - cheap and reproducible, meant for exporting a
ticket-ready summary after `analyze_webpage` has run.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


def build_result(url: str, render: bool = False) -> dict:
    """Fetch + run the full pipeline (heuristic score, and the trained ML
    classifier when available), returning one result dict with a single
    combined verdict instead of two opinions the caller has to reconcile.

    render=True fetches through a headless browser (websec_agent.render)
    instead of a plain HTTP GET, so JS-injected content is visible - slower
    and requires requirements-render.txt, so it's opt-in."""
    from . import verdict as vd
    from . import web_analysis as wa

    if render:
        from . import render as rnd

        fetched = rnd.fetch_rendered_html(url)
    else:
        fetched = wa.fetch_html(url)
    html = fetched["html"]
    structure = wa.analyze_structure(html, fetched["final_url"])
    iocs = wa.extract_iocs(html, fetched["final_url"])
    heuristic = wa.score_phishing(html, structure, iocs, fetched["final_url"])

    ml = None
    try:
        from . import classifier as clf

        ml = clf.classify_webpage(html, fetched["final_url"])
    except RuntimeError:
        pass  # MLOps extras not installed, or no trained model yet - degrade gracefully

    from urllib.parse import urlsplit

    from . import domain_age as da

    domain_age_info = da.lookup_domain_age(urlsplit(fetched["final_url"]).hostname or "")

    return {
        "requested_url": url,
        "final_url": fetched["final_url"],
        "status_code": fetched["status_code"],
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "structure": structure,
        "iocs": iocs,
        "phishing_heuristic": heuristic,
        "ml_classifier": ml,
        "domain_age": domain_age_info,
        "verdict": vd.combine_verdicts(heuristic, ml, domain_age_info),
    }


def build_markdown_report(result: dict) -> str:
    structure = result["structure"]
    iocs = result["iocs"]
    heuristic = result["phishing_heuristic"]
    ml = result.get("ml_classifier")
    domain_age = result.get("domain_age")
    combined = result.get("verdict")

    forms_lines = "\n".join(
        f"  - action=`{f['action']}` method={f['method']} "
        f"password_field={f['has_password_field']} external={f['action_is_external']}"
        for f in structure["forms"]
    ) or "  - (none)"

    reasons_lines = "\n".join(f"- {r}" for r in heuristic["reasons"]) or "- (none)"

    def _list_or_none(values):
        return ", ".join(values) if values else "(none)"

    verdict_section = ""
    if combined:
        ml_line = (
            f"- **Classifieur ML** : {ml['label']} (probabilité phishing {ml['phishing_probability']:.2f})"
            if ml
            else "- **Classifieur ML** : indisponible (extras MLOps non installés ou pas de modèle entraîné)"
        )
        if domain_age and domain_age.get("age_days") is not None:
            age_line = f"- **Âge du domaine** : {domain_age['age_days']} jours (enregistré le {domain_age['registered_at']})"
        elif domain_age and domain_age.get("is_platform_hosted"):
            age_line = "- **Âge du domaine** : non significatif (sous-domaine d'un hébergeur PaaS)"
        else:
            age_line = "- **Âge du domaine** : indisponible"
        verdict_section = f"""
## Verdict combiné

**{combined['label'].upper()}** — {combined['confidence']}

- **Score heuristique** : niveau {heuristic['level']} (score {heuristic['score']})
{ml_line}
{age_line}
"""

    return f"""# Rapport de triage web — {result['requested_url']}

- **URL finale** : {result['final_url']}
- **Code HTTP** : {result['status_code']}
- **Récupéré le** : {result['fetched_at']}
- **Titre de la page** : {structure['title'] or '(aucun)'}
{verdict_section}
## Score heuristique de phishing

**Niveau : {heuristic['level'].upper()}** (score {heuristic['score']})

Raisons :
{reasons_lines}

## Structure

- Formulaires :
{forms_lines}
- Scripts externes : {_list_or_none(structure['external_scripts'])}
- Iframes : {_list_or_none(structure['iframes'])}
- Favicon externe : {structure['favicon_is_external']}
- Meta-refresh : {structure['meta_refresh']}

## Indicateurs de compromission (IOC)

- Domaines référencés : {_list_or_none(iocs['domains'])}
- Emails : {_list_or_none(iocs['emails'])}
- Domaines punycode : {_list_or_none(iocs['punycode_domains'])}
- Liens raccourcis : {_list_or_none(iocs['shortener_links'])}
- URLs en IP brute : {_list_or_none(iocs['ip_literal_urls'])}
- TLD suspects : {_list_or_none(iocs['suspicious_tld_domains'])}

---
*Score heuristique, pas un verdict certain - à corroborer avec une source de threat intel (urlscan.io, VirusTotal, PhishTank) avant action.*
"""


def build_ioc_bundle(result: dict) -> dict:
    """A small, tool-agnostic IOC bundle - easy to paste into a ticket or
    feed into another tool, without the prose/structure sections."""
    iocs = result["iocs"]
    indicators = []
    indicators.append({"type": "url", "value": result["final_url"]})
    for d in iocs["domains"]:
        indicators.append({"type": "domain", "value": d})
    for e in iocs["emails"]:
        indicators.append({"type": "email", "value": e})
    for u in iocs["ip_literal_urls"]:
        indicators.append({"type": "url-ip-literal", "value": u})
    for d in iocs["punycode_domains"]:
        indicators.append({"type": "domain-punycode", "value": d})

    combined = result.get("verdict")
    ml = result.get("ml_classifier")
    domain_age = result.get("domain_age")
    return {
        "source_url": result["requested_url"],
        "fetched_at": result["fetched_at"],
        "verdict_label": combined["label"] if combined else None,
        "verdict_level": result["phishing_heuristic"]["level"],
        "verdict_score": result["phishing_heuristic"]["score"],
        "ml_phishing_probability": ml["phishing_probability"] if ml else None,
        "domain_age_days": domain_age["age_days"] if domain_age else None,
        "indicators": indicators,
    }


def export(url: str, out_dir: str, render: bool = False) -> dict:
    """Run the pipeline and write report.md + iocs.json into out_dir.
    Returns {"result": ..., "report_path": ..., "ioc_path": ...}."""
    import os

    os.makedirs(out_dir, exist_ok=True)
    result = build_result(url, render=render)

    report_path = os.path.join(out_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(build_markdown_report(result))

    ioc_path = os.path.join(out_dir, "iocs.json")
    with open(ioc_path, "w", encoding="utf-8") as f:
        json.dump(build_ioc_bundle(result), f, indent=2, ensure_ascii=False)

    return {"result": result, "report_path": report_path, "ioc_path": ioc_path}
