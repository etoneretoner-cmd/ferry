# Déploiement public de la passerelle agents

La passerelle tourne et est testée en local. Pour la rendre joignable par des
agents externes, l'héberger (gratuit) — le tunnel sortant est bloqué depuis le
VM, donc l'hébergement externe est obligatoire.

## Option A — Render (recommandé, gratuit)

1. Créer un compte sur https://render.com (compte d'Antoine).
2. New → Web Service → connecter le dossier `~/workspace/gateway`
   (via repo Git ou upload) — ou déployer le Dockerfile.
3. Variables d'environnement :
   - `BRIDGE_TOKEN` = chaîne aléatoire de 64 caractères hexadécimaux
     (générer : `python3 -c "import secrets; print(secrets.token_hex(32))"`)
4. Noter l'URL publique, ex. `https://passerelle-agents.onrender.com`.

## Option B — Fly.io (gratuit)

1. `fly launch` dans `~/workspace/gateway` (compte d'Antoine).
2. `fly secrets set BRIDGE_TOKEN=<64 hex>`.
3. `fly deploy`. Noter l'URL publique.

## Après le déploiement

1. Copier la valeur de `BRIDGE_TOKEN` dans `~/workspace/gateway/bridge_token`
   (fichier 600) — c'est ce que le cron pont utilise pour s'authentifier.
2. Écrire l'URL publique dans `~/workspace/gateway/bridge_target`
   (ex. `https://passerelle-agents.onrender.com`) — le cron pont bascule
   automatiquement dessus (défaut : `http://127.0.0.1:8000`).
3. Vérifier : `curl https://<url>/v1/status` → `{"ok":true,...}`.
4. Protocole agent public : `https://<url>/protocol`.

## Notes

- La base SQLite du déploiement est éphémère (agents à ré-enregistrer après
  redéploiement) — acceptable pour le pilote ; le registre de référence reste
  l'artefact privé.
- Base de données et token : permissions 600, jamais dans les logs.
- Journal d'audit : table `audit` dans `gateway.db`.
