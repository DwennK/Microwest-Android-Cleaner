# Microwest Android Cleaner

Application desktop d'atelier : **Tauri 2 + Rust**, **React + TypeScript + Vite**, **Tailwind CSS + composants shadcn/ui adaptés à Microwest**, **SQLite**. L'application distribuée ne nécessite ni Python ni serveur Node.js.

Elle analyse uniquement les métadonnées des applications Android connectées par ADB. Aucune désinstallation automatique : une confirmation native, contrôlée par Rust, est obligatoire avant la seule commande de suppression autorisée :

```text
adb -s SERIAL shell pm uninstall --user 0 PACKAGE
```

Les applications système, protégées, conservées par le technicien, déjà retirées ou dont les métadonnées sont incomplètes ne peuvent pas être sélectionnées pour suppression. Un scan complet, réel et lié au même téléphone est requis. Les flags système sont relus avant chaque suppression. Aucun `root`, `su`, `rm` ni lecture de données personnelles n'est exposé.

## Démarrer en développement

Windows : Node.js 24, Rust stable avec la cible MSVC, outils de compilation Visual Studio C++/Windows SDK, WebView2. Les binaires Windows ADB et aapt2 présents dans le dépôt sont utilisés en priorité.

```powershell
npm ci
npm run tauri dev
```

`npm run dev` seul montre la présentation dans un navigateur ; les commandes système fonctionnent uniquement dans Tauri. Le mode démonstration, activé explicitement dans les paramètres de l'application desktop, utilise trois applications fictives et interdit toute suppression.

## Tester et construire

```powershell
npm run typecheck
npm test
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets --features test-support -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --locked --features test-support
npm run build:desktop
```

Les installateurs sont écrits dans `src-tauri/target/release/bundle/nsis/` et `src-tauri/target/release/bundle/msi/`. Le workflow Windows produit ces fichiers en artefacts GitHub Actions, sans publier de release. Voir [distribution et signature](docs/DISTRIBUTION.md).

Les tests Rust comprennent 600 comparaisons générées et 49 évaluations issues directement des tests Python existants, les parsers, SQLite, les rapports, les garde-fous IA et de suppression. Un exécutable ADB **simulé**, compilé uniquement avec `test-support`, teste le parcours complet et les processus : détection, scan, annulation, déconnexion, timeout et drainage des sorties. Ces tests ne constituent pas une validation sur un téléphone réel.

## Utilisation

1. **Connexion** : sélectionner un téléphone autorisé. Accepter le débogage USB sur son écran si l'état est `unauthorized`. Réparer ADB ou produire un diagnostic si nécessaire.
2. **Analyse du téléphone** : lancer un scan utilisateur, avec inclusion optionnelle des applications système. Annuler interrompt le processus courant et empêche l'enregistrement d'une référence complète.
3. **Applications** : filtrer par nom/package/note, action, visibilité, installateur, permission ou score. Ouvrir une fiche pour voir les raisons, accès déclarés/accordés/actifs, rôles HOME, notes et validation technicien.
4. **Analyse IA**, facultative : confirmer l'envoi des métadonnées au fournisseur configuré. L'IA ne reçoit ni numéro ADB ni notes ; ses résultats respectent les protections locales et les décisions humaines.
5. **Désinstaller la sélection** : confirmer la liste et le téléphone dans la boîte native. Les résultats et décisions sont conservés dans SQLite ; rescanner après intervention.
6. **Rapports & historique** : export HTML imprimable, CSV et plan d'action texte, comparaison au scan précédent du même téléphone, consultation des 100 derniers scans.

ADB est recherché dans les ressources embarquées, le dossier de données, `ADB_PATH`, les SDK `ANDROID_HOME`/`ANDROID_SDK_ROOT`, le PATH et les emplacements usuels. aapt2 est recherché dans `tools`, `adb`, `AAPT2_PATH`, le PATH et les dossiers SDK `build-tools`. Sans aapt2, les libellés sont dérivés du package ; l'absence d'une icône raster est explicitement indiquée. Les icônes adaptatives XML ne sont pas rasterisées.

Un helper de développement remplace l'ancien installateur Python d'aapt2 : `node scripts/install-aapt2.mjs`. Il conserve un binaire existant ; sinon il vérifie l'empreinte d'une archive officielle à version fixe. `--update` force cette mise à jour. Les notices Android sont incluses dans les installateurs.

## Données et migration

- En développement : `data`, `cache`, `logs`, `reports` et `.env` à la racine du dépôt.
- Application installée : dossier local utilisateur renvoyé par Tauri, visible dans **Paramètres → Environnement local**.
- Mode portable : créer `portable.flag` à côté de l'exécutable, dans un emplacement accessible en écriture. Un ancien `data/app_reputation.sqlite` voisin est également reconnu. Les ressources `adb/` et `tools/` doivent accompagner l'exécutable portable.
- `MICROWEST_DATA_DIR` permet d'imposer le dossier racine de données. Il contient ensuite `data/app_reputation.sqlite`, `data/ui_settings.json`, etc.

Les schémas SQLite historiques 0–3 sont migrés explicitement en version 4 : les tables existantes sont conservées et `scan_payloads` ajoute les métadonnées détaillées des nouveaux scans. Une sauvegarde SQLite cohérente `app_reputation.schemaN_backup_*.sqlite` est créée avant migration. Une base plus récente est refusée sans modification. Les validations historiques globales v2 sont replacées uniquement sur leurs snapshots, jamais propagées à d'autres clients. L'empreinte de téléphone conserve l'algorithme SHA-256 tronqué à 24 caractères ; le numéro ADB brut n'est pas stocké dans les nouveaux snapshots.

Pour reprendre un autre dossier Python : **Paramètres → Importer un dossier**. Choisir la racine contenant `data/app_reputation.sqlite`. Le moteur prépare une copie, valide base/réglages, demande une confirmation, puis conserve les données précédentes dans `backup-import-*`. Le dossier source reste intact. L'historique Python ne contenait pas toutes les permissions et raisons : ces détails sont indiqués comme indisponibles, jamais reconstitués artificiellement. Les anciennes icônes pourront être récupérées au prochain scan.

Ne pas ouvrir simultanément la même base avec l'ancienne application Python. Pour revenir à Python, utiliser la sauvegarde du schéma précédent dans un dossier séparé.

Les réglages `ai_provider`, `openai_model`, `openai_base_url`, `minimax_model`, `minimax_base_url` et les clés `.env` existants restent compatibles. Les variables d'environnement du processus ont priorité pour les clés. Les nouvelles clés sont enregistrées par Rust dans le `.env` du dossier de données, au même format que l'ancienne application ; ce fichier local n'est pas chiffré. Il n'est ni renvoyé au frontend, ni inclus dans les rapports, ni versionné. HTTPS est imposé aux fournisseurs distants ; localhost HTTP est accepté pour un fournisseur local.

## Architecture et référence Python

`src/App.tsx` compose la navigation et les cinq écrans de `src/pages/`. `src/hooks/useAppController.ts` conserve l’état et les actions partagés entre les écrans ; `useOperation.ts` centralise le verrouillage immédiat, les messages, la progression et l’annulation des opérations. Les composants communs et la fiche d’application sont dans `src/components/`. Les espacements, couleurs et styles de contrôle communs sont dans `src/styles.css`.

`src-tauri/src/` sépare modèle, ADB/processus, métadonnées APK, règles, workflow, SQLite, IA, rapports et commandes Tauri. Le rapport HTML embarque `report.css` et reste autonome, avec des fiches détaillées par application et une mise en page A4 à l’impression. Les opérations longues sont asynchrones et la progression utilise `operation-progress`. Une exclusion mutuelle empêche deux scans, modifications ou suppressions simultanés. Aucune commande shell générale, permission filesystem frontend ou accès réseau frontend n'est exposé.

L'ancienne application, ses tests et son packaging sont isolés dans `legacy/python/` comme référence temporaire, **exclus de la distribution et du build courant**. Ils restent disponibles jusqu'à validation matérielle de la nouvelle application. Il n'existe aucun pont Rust–Python. [Inventaire de migration](docs/MIGRATION.md) · [Vérifications et limites](docs/VALIDATION.md).

Pour régénérer les références uniquement pendant le développement : installer pytest, python-dotenv et le SDK OpenAI dans un environnement Python séparé, puis lancer `python scripts/reference-fixtures.py` et `cargo fmt --manifest-path src-tauri/Cargo.toml`. Le helper ne participe jamais au build ou à l'exécution distribuée.
