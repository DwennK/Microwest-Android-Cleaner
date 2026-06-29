# Microwest Android Cleaner

Application interne pour magasin de réparation smartphone. Elle détecte un téléphone Android/Samsung via ADB USB, scanne les applications installées, calcule un score de risque local, permet une analyse IA optionnelle et exporte un rapport client.

L'application ne lit pas les données personnelles du client. Elle analyse uniquement les métadonnées des applications installées : package, installateur, permissions sensibles, version, état, date d'installation si disponible.

## Règle de sécurité

La désinstallation automatique est interdite. Une validation humaine est toujours demandée avant toute suppression.

La seule commande de suppression utilisée est :

```powershell
adb shell pm uninstall --user 0 PACKAGE
```

L'application n'utilise pas `adb root`, `su`, `rm`, `settings` dangereux, ni `content read`.

## Installation

Prérequis :

- Windows, macOS ou Linux
- Python 3.12 ou plus récent
- Un câble USB fonctionnel
- ADB disponible

Depuis le dossier `microwest_android_cleaner` :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

Sur macOS ou Linux :

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Scripts portables inclus :

```bash
./setup_mac.command
./run_mac.command
```

Sur Windows :

```bat
run_windows.bat
```

## Développement

Le projet cible Python 3.12. Pour lancer la suite locale :

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
```

Les fichiers produits à l'exécution restent locaux et ne doivent pas être versionnés : base SQLite portable, logs, rapports exportés et cache d'icônes. Les dossiers conservent seulement leurs `.gitkeep`.

## Packaging installable

Une cible PyInstaller est fournie pour créer un bundle desktop depuis le poste de build. Elle reste volontairement explicite sur les binaires Android à embarquer :

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python packaging/build_pyinstaller.py --include-adb --include-aapt2
```

Sur Windows :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python packaging\build_pyinstaller.py --include-adb --include-aapt2
```

Options utiles :

- `--include-adb` embarque les fichiers présents dans `adb/` ;
- `--include-aapt2` embarque les fichiers présents dans `tools/` ;
- `--icon chemin/icone.icns` ou `--icon chemin/icone.ico` ajoute une icône native ;
- `--print-command` affiche la commande PyInstaller sans construire.

Le résultat est écrit dans `dist/`. Les dossiers `build/`, `dist/` et `packaging/generated/` ne sont pas versionnés.

## Intégration continue

Le workflow GitHub Actions `.github/workflows/tests.yml` installe `requirements-dev.txt`, lance `ruff` puis `pytest` sur Python 3.12 à chaque push et pull request.

## Installer ADB

Option 1 : placer le binaire ADB compatible avec votre système dans :

```text
microwest_android_cleaner/adb/adb
```

Sur Windows, le binaire attendu est :

```text
microwest_android_cleaner/adb/adb.exe
microwest_android_cleaner/adb/AdbWinApi.dll
microwest_android_cleaner/adb/AdbWinUsbApi.dll
```

Option 2 : installer Android Platform Tools et ajouter le dossier au `PATH`.

Sur macOS avec Homebrew :

```bash
brew install android-platform-tools
```

L'application cherche d'abord le binaire local adapté au système (`adb/adb.exe` sur Windows, `adb/adb` sur macOS/Linux), puis `adb` dans le `PATH`.

## Nom réel des applications avec aapt2

L'application peut utiliser `aapt2` pour lire le vrai nom affiché dans l'APK installé. Cela aide à repérer les apps qui cachent un package banal mais affichent un nom de type `Cleaner`, `Security`, `Weather`, `Contacts` ou `System Update`.

Emplacement utilisé sur macOS/Linux :

```text
microwest_android_cleaner/tools/aapt2
```

Emplacement utilisé sur Windows :

```text
microwest_android_cleaner/tools/aapt2.exe
```

Pendant le scan, l'application récupère temporairement le fichier APK installé, lit uniquement ses métadonnées publiques avec `aapt2 dump badging`, puis supprime le fichier temporaire. Elle ne lit pas les données personnelles du client.

Si `aapt2` est absent, le scan continue avec un nom dérivé du package.

Quand une icône raster est disponible dans l'APK (`png`, `webp`, `jpg`), elle est extraite dans :

```text
microwest_android_cleaner/cache/app_icons/
```

Les icônes adaptives Android en XML peuvent ne pas être affichées si aucun fichier image direct n'est présent.

## Préparer le téléphone Android

1. Ouvrir les paramètres Android.
2. Aller dans `À propos du téléphone`.
3. Appuyer 7 fois sur `Numéro de build` pour activer les options développeur.
4. Revenir aux paramètres, ouvrir `Options développeur`.
5. Activer `Débogage USB`.
6. Connecter le téléphone par USB.
7. Accepter la demande d'autorisation RSA sur l'écran du téléphone.

Si l'état affiché est `unauthorized`, le client doit accepter le débogage USB sur le téléphone.

Le bouton `Redémarrer ADB` relance le daemon ADB local avec `adb kill-server` puis `adb start-server`. Un clic droit sur ce bouton permet aussi de choisir `Démarrer daemon ADB` ou `Arrêter daemon ADB`.

Le bouton `Diagnostic ADB` affiche un rapport local :

- système détecté, version Python/Qt et dossier portable utilisé ;
- accès en écriture aux dossiers `data`, `logs`, `cache` et `reports` ;
- chemin et version du binaire `adb` utilisé ;
- disponibilité optionnelle de `aapt2` ;
- sortie brute `adb devices -l` ;
- état du téléphone sélectionné avec conseils adaptés.

Le bouton `Réparer connexion` relance ADB, attend brièvement, relit `adb devices -l`, puis met à jour la sélection téléphone. Il est utile après un état `offline`, `unauthorized`, un câble changé ou un téléphone rebranché.

Si plusieurs téléphones sont connectés, la liste `Appareil` permet de choisir explicitement le numéro ADB à scanner. En mode `Auto`, l'application choisit le premier appareil autorisé (`device`) retourné par ADB.

L'application rafraîchit aussi périodiquement la liste ADB quand elle est inactive. Le rafraîchissement ne lance aucun scan automatiquement.

Les boutons `Copier diagnostic` et `Exporter diagnostic` permettent de transmettre le dernier rapport ADB sans ouvrir les fichiers de logs.

## Mode portable

L'application reste portable : les fichiers runtime restent dans le dossier de l'application.

```text
microwest_android_cleaner/data/
microwest_android_cleaner/logs/
microwest_android_cleaner/cache/
microwest_android_cleaner/reports/
microwest_android_cleaner/adb/
microwest_android_cleaner/tools/
```

Le diagnostic vérifie que ces dossiers sont créables et accessibles en écriture. Aucun déplacement vers `~/Library` n'est requis sur macOS.

## Utilisation

L'interface est organisée en onglets pour garder le tableau lisible même en plein écran :

- `Connexion` : état détaillé du téléphone, sélection ADB, diagnostic et réparation ADB ;
- `Scan` : lancement du scan, annulation, progression et option d'inclusion des apps système ;
- `Résultats` : tableau pleine largeur, recherche, filtres, sélection et actions de triage ;
- `Détails` : fiche complète de l'application sélectionnée ;
- `Exports` : rapports, CSV, plan d'action et historique ;
- `Paramètres` : mode démo, choix du provider IA, clé API, modèle, base URL, maintenance locale et accès aux dossiers portables.

Flux recommandé :

1. Dans `Connexion`, cliquer sur `Détecter téléphone`.
2. Vérifier le modèle, la version Android et le numéro ADB.
3. Dans `Scan`, cliquer sur `Scanner les apps`.
4. Suivre la barre de progression. Le bouton `Annuler scan` arrête proprement le scan en cours.
5. À la fin du scan, l'application ouvre automatiquement `Résultats`.
6. Examiner les scores, filtrer la liste et sélectionner les apps à vérifier.
7. Double-cliquer une ligne ou utiliser `Voir détails` pour ouvrir l'onglet `Détails`.
8. Cocher uniquement les applications validées manuellement.
9. Cliquer sur `Désinstaller sélection`.
10. Confirmer la liste affichée.
11. Dans `Exports`, générer un rapport client avec `Exporter rapport`, ou une table brute avec `Exporter CSV`.

Par défaut, seules les applications utilisateur sont scannées. La case `Afficher apps système` permet de les afficher aussi, mais les applications système Samsung/Google/Microsoft connues sont marquées `do_not_touch`.

Le statut global reste visible dans l'en-tête. Les informations complètes du téléphone sont dans `Connexion` pour ne pas réduire la zone du tableau.

Le bouton `Paramètres app` dans `Résultats` ouvre sur le téléphone la fiche Android de l'application sélectionnée. Il utilise une commande ADB non destructive :

```powershell
adb shell am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:PACKAGE
```

Les filtres de l'onglet `Résultats` permettent d'isoler rapidement les apps peu visibles ou capables de générer du spam de notifications. L'application ne lit pas le contenu des notifications.

Filtres supplémentaires :

- `Sideload` pour isoler les apps sans installateur connu ou hors Google Play/Galaxy Store ;
- `Score min` pour afficher uniquement les apps au-dessus d'un seuil ;
- `Toutes permissions` pour filtrer par famille de permissions sensibles.

La synthèse au-dessus du tableau `Résultats` affiche le nombre total d'apps, les apps à traiter, les apps à vérifier, les apps cachées, les apps sideload et les lignes cochées.

Boutons de triage :

- `Cocher à traiter` coche les apps utilisateur à score élevé proposées pour validation humaine ;
- `Cocher review` coche les apps à vérifier manuellement ;
- `Tout décocher` remet la sélection à zéro ;
- `Note sélection` ajoute une note locale persistante au package sélectionné ;
- clic droit sur une ligne puis `Note technicien` permet aussi de gérer la note ;
- double-clic sur une ligne ouvre l'onglet `Détails` avec la fiche complète.

Les notes technicien sont conservées dans la base SQLite portable et apparaissent dans les détails, le CSV et le rapport HTML.

Dans `Exports`, le bouton `Plan action` exporte un fichier texte dans `reports/` avec les apps à valider, les raisons principales et les commandes ADB exactes à n'utiliser qu'après validation humaine. `Copier plan` place le même plan dans le presse-papiers. `Ouvrir rapports` ouvre le dossier portable `reports/`.

Dans `Paramètres`, le bouton `Mode démo` charge un faux téléphone et des apps fictives pour tester l'interface sans Android branché, puis ouvre `Résultats`. Le choix du provider IA masque automatiquement les champs de l'autre provider. Les boutons `Ouvrir dossier data`, `Ouvrir logs` et `Recharger blacklist/whitelist` regroupent la maintenance locale. Le bouton `Historique` dans `Exports` affiche les derniers scans enregistrés dans la base SQLite portable.

## Détection des apps suspectes

Le score local combine plusieurs signaux. Une app n'est pas déclarée malveillante avec certitude : elle est remontée pour vérification humaine.

Signaux utilisés :

- noms/packages de type cleaner, booster, antivirus, météo, VPN/proxy, QR/PDF scanner, wallpaper, horoscope, app lock, flashlight ;
- mots liés aux arnaques : cash, loan, credit, win, reward, earn, gift, cadeau, gratuit, lottery, casino ;
- imitation système par une app utilisateur, par exemple un package commençant par `com.android.` ou `com.google.` sans être une app système ;
- app utilisateur sans icône visible dans le launcher ;
- identité peu claire : nom très générique, nom réel non récupéré, icône non récupérée ou adaptive XML ;
- audit notifications : accès notifications, demande `POST_NOTIFICATIONS`, démarrage automatique, alarmes exactes, vibration ;
- installateur inconnu ou sideload ;
- overlay, accessibilité, administrateur appareil, accès notifications ;
- SMS, appels, contacts, statistiques d'utilisation, installation d'apps inconnues ;
- combinaison à fort risque : cleaner/booster + overlay/accessibilité/notifications ;
- app lancée au démarrage avec nom suspect ;
- target SDK ancien ;
- package très générique ou semblant aléatoire.

## Analyse IA optionnelle

L'analyse IA utilise OpenAI par défaut, ou MiniMax si `AI_PROVIDER=minimax` est configuré. Le provider, la clé API, le modèle et la base URL peuvent aussi être choisis dans l'onglet `Paramètres`.

Créer un fichier `.env` à côté de `main.py` :

```text
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4.1-mini
```

Pour MiniMax :

```text
AI_PROVIDER=minimax
MINIMAX_API_KEY=...
MINIMAX_MODEL=MiniMax-M3
MINIMAX_BASE_URL=https://api.minimax.io/v1
```

Si la clé du provider choisi est absente, le bouton IA est désactivé. L'onglet `Paramètres` affiche l'état de la clé attendue.

Pour ajouter une clé depuis l'interface, sélectionner le provider, coller la clé dans `Clé API`, puis cliquer sur `Enregistrer paramètres`. Le champ est vidé après sauvegarde et la clé est écrite dans `.env`.

Les préférences choisies dans l'interface sont enregistrées ici :

```text
data/ui_settings.json
```

Ce fichier reste local et portable. Les clés API restent dans `.env`, qui est ignoré par Git.

L'IA reçoit uniquement :

- nom d'application
- package
- installateur
- permissions sensibles
- statut système ou utilisateur
- score local
- raisons locales
- version
- date d'installation si disponible

Elle ne reçoit jamais contacts, SMS, photos, fichiers, comptes, numéros de téléphone ou historique.

## Base locale

La base SQLite est créée automatiquement ici :

```text
data/app_reputation.sqlite
```

Tables :

- `whitelist(package TEXT PRIMARY KEY, label TEXT, reason TEXT)`
- `blacklist(package TEXT PRIMARY KEY, label TEXT, reason TEXT, severity INTEGER)`
- `scan_history(id INTEGER PRIMARY KEY, date TEXT, device_model TEXT, android_version TEXT, scanned_count INTEGER, suspicious_count INTEGER)`
- `uninstall_history(id INTEGER PRIMARY KEY, date TEXT, package TEXT, app_label TEXT, result TEXT)`

La whitelist initiale contient des applications courantes Google, Samsung, Microsoft, WhatsApp, Instagram, Spotify et Netflix.

La blacklist initiale est vide volontairement : aucun vrai package n'est marqué comme malware confirmé sans preuve ou ajout manuel. Depuis le clic droit dans la table, un technicien peut ajouter un package à la blacklist ou à la whitelist locale.

## Rapports

Les rapports HTML sont générés dans :

```text
reports/
```

Format de nom :

```text
rapport_android_cleaner_YYYY-MM-DD_HH-MM.html
```

Chaque rapport mentionne que le classement est une aide au diagnostic basée sur des métadonnées et qu'aucune donnée personnelle du client n'a été lue.

## Créer un EXE plus tard

Exemple PyInstaller :

```powershell
pip install pyinstaller
pyinstaller --noconfirm --windowed --name MicrowestAndroidCleaner main.py
```

Copier ensuite les dossiers `adb`, `data`, `reports` et `logs` à côté de l'exécutable si nécessaire.
