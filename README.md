# AegisSOC

Application de centre opérationnel de sécurité (SOC) conçue pour la démonstration et l’apprentissage : tableau de bord, triage d’alertes, suivi d’incidents, mémoire d’investigation, analyse locale de journaux et journal d’activité.

## Lancer en local

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Avant le premier lancement, définissez un mot de passe administrateur fort dans `ADMIN_PASSWORD`, puis ouvrez http://127.0.0.1:5000 et connectez-vous avec `admin` et ce mot de passe. Exemple PowerShell : `$env:ADMIN_PASSWORD = "un-mot-de-passe-fort"`. La base `centralsoc.db` et ses données d’exemple sont créées au premier lancement. Supprimez cette base pour réinitialiser la démo.

## Configuration

Définissez `SECRET_KEY` avec une valeur aléatoire et `ADMIN_PASSWORD` avec un secret fort lors de la création initiale de la base. Vous pouvez définir `DATABASE_PATH` pour choisir l’emplacement de SQLite et `PORT` pour le port HTTP. `FLASK_DEBUG=1` active le débogage et ne doit pas être utilisé en production.

## Fonctions

- Authentification par session Flask et mots de passe hachés avec Werkzeug.
- Alertes avec sévérité, score de risque et flux de triage.
- Création d’incidents et de notes d’investigation avec références aux preuves.
- Analyse pédagogique de journaux par règles, sans transfert externe des données.
- Journalisation des actions dans une base SQLite locale.
- Interface responsive en français, adaptée à une console SOC.

## Limites et sécurité

Cette application est un prototype pédagogique, pas un SIEM ni un service certifié. Les règles sont illustratives; l’analyse ne remplace ni une corrélation de production ni une revue humaine. Avant un déploiement réel : ajouter une gestion complète des rôles et du MFA, CSRF, limitation des tentatives de connexion, migrations, sauvegardes, stockage de preuves immuable, chiffrement adapté, supervision et tests de sécurité. Protégez le compte de démo et remplacez son secret avant toute exposition réseau. SQLite convient à la démonstration mono-instance; pour un usage partagé, migrer le stockage vers PostgreSQL et renforcer la configuration de déploiement.

## Arborescence

- `app.py` — routes API, authentification, schéma et données de démonstration.
- `templates/index.html` — interface de la console.
- `static/style.css` — thème responsive.
- `static/app.js` — navigation et interactions.

### Déploiement Docker

Copiez `.env.example` vers `.env`, remplacez `SECRET_KEY` et `ADMIN_PASSWORD` par des secrets forts, puis lancez `docker compose up --build -d`. La base persiste dans le volume `centralsoc-data`. Configurez `COOKIE_SECURE=1` lorsque le trafic passe par HTTPS. Chaque instance initialise son compte `admin` avec la valeur configurée dans `ADMIN_PASSWORD`.

`COOKIE_SECURE=1` active le drapeau Secure des cookies. `DATABASE_PATH` choisit l’emplacement de SQLite. `PORT` choisit le port HTTP. SQLite convient à une démo mono-instance; PostgreSQL n’est pas encore branché à cette version.

