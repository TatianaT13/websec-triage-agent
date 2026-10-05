# agentaai — agent de triage web-sécu (Claude Agent SDK)

Agent construit avec le [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk) pour l'analyse défensive de pages web : audit de structure HTML, extraction d'IOC, et score heuristique de phishing. Un outil optionnel basé sur [MarkupLM](https://huggingface.co/docs/transformers/model_doc/markuplm) permet de poser des questions sur le contenu d'une page (QA sur document HTML).

## ⚠️ Cadre d'usage

Cet outil est destiné à un usage défensif et autorisé uniquement : tes propres sites, des échantillons de phishing déjà signalés, des labs/CTF. Il ne contourne aucune protection et ne doit pas être pointé vers des cibles sans autorisation.

## Fonctionnalités

- **`analyze_webpage`** : fetch sécurisé (garde-fou anti-SSRF, taille limitée) + structure de la page (formulaires, scripts externes, iframes, favicon) + IOC (domaines, emails, domaines punycode, URLs en IP brute, TLD suspects) + score de phishing heuristique avec raisons.
- **`ask_webpage`** (optionnel, nécessite les dépendances ML) : QA en langage naturel sur le contenu d'une page via MarkupLM.

## Installation

Le SDK pilote le CLI Claude Code en arrière-plan (nécessite Node.js) :

```bash
npm install @anthropic-ai/claude-code

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# optionnel, pour ask_webpage :
pip install -r requirements-ml.txt
```

Authentification : connecte-toi avec `node_modules/.bin/claude` (login intégré), ou définis la variable d'environnement `ANTHROPIC_API_KEY` (voir `.env.example`).

## Utilisation

```bash
python main.py "Analyse https://example.com et dis-moi si ça ressemble à du phishing"
```

## Structure du projet

```text
.
├── main.py                     # point d'entrée de l'agent
├── websec_agent/
│   ├── web_analysis.py         # fetch + heuristiques (structure, IOC, score phishing, QA MarkupLM)
│   └── mcp_server.py           # déclaration des outils exposés à l'agent
├── requirements.txt
├── requirements-ml.txt
└── .env.example
```

## Limites connues

- Le score de phishing est **heuristique** (règles), pas un modèle entraîné : à affiner avec de vrais échantillons.
- MarkupLM est un backbone de compréhension de document HTML (QA, extraction d'info) — il n'est pas pré-entraîné pour classifier du phishing ; `ask_webpage` sert à interroger le contenu, pas à obtenir un verdict de sécurité direct.
- Pas de rendu JavaScript : le HTML est analysé tel que reçu, sans exécution de scripts (ok pour l'instant, à étendre avec un headless browser si besoin des pages fortement dynamiques).

## Prochaines étapes possibles

- Générateur de rapport (résumé lisible + bundle IOC exportable, ex. pour un ticket SOC).
- Règles de scoring affinées avec de vrais échantillons de phishing.
- Rendu JS (headless browser) pour les pages fortement dynamiques.
