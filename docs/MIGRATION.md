# Migration vers Tauri 2

Branche : `codex/tauri-rust-migration`. État initial : arbre de travail propre, aucun AGENTS.md dans le dépôt. L'application Python reste temporairement une référence, sans pont d'exécution avec Rust.

## Inventaire de parité

| Domaine | Fonctions à conserver |
| --- | --- |
| Connexion | ADB embarqué, variables ADB_PATH/SDK, PATH et emplacements usuels ; liste détaillée, sélection auto/explicite, unauthorized/offline/disconnected, propriétés, rafraîchissement, daemon démarrer/arrêter/redémarrer, réparation, diagnostic copiable/exportable |
| Scan | Utilisateur/système, installateur, dumpsys, version/SDK/date/état, permissions demandées/accordées, capacités actives via lectures settings/appops/device_policy, launcher, HOME utilisateur courant et accueil actif |
| APK | Recherche aapt2, APK temporaire, libellé français et replis, extraction raster/cache, repli package si absent |
| Risque | Ensemble des règles risk_rules.py et app_triage.py, plafonds/planchers, whitelist/blacklist, distinction déclaré/actif, politique atelier et noms signalés, protection système/officielle |
| IA | OpenAI/MiniMax compatibles chat completions, modèles/URL/clé, lots de 20, inventaire, JSON strict, retry des verdicts manquants, garde-fous locaux et humains |
| SQLite | Schémas historiques 0–3, sauvegarde avant évolution, whitelist initiale, réputation, notes par package, scans/snapshots, empreinte SHA-256 du téléphone, validations par scan, historique de désinstallation, comparaison |
| Atelier | Recherche/filtres/tri, sélection des priorités/review, détails, notes, validations, réputation, réglages Android, confirmation avant suppression, uniquement pm uninstall --user 0 |
| Exports | Rapport HTML échappé, CSV, plan texte avec commandes, diagnostic texte, presse-papiers, dossiers locaux |
| Application | Réglages JSON/.env compatibles, mode démo explicitement fictif, progression/annulation/erreurs, opérations asynchrones, dossier de données portable ou utilisateur |
| Distribution | React statique incorporé, moteur Rust natif, aucune dépendance Python/serveur Node distribuée, NSIS/MSI, CI et signature documentée |

Les essais sur téléphone réel et les signatures nécessitent du matériel et des certificats disponibles. Ils doivent être distingués des tests automatisés.
