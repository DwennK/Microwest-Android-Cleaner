# Distribution Windows

`npm ci` puis `npm run build:desktop` produisent un exécutable natif, un seul installateur EXE (NSIS) par utilisateur. Les ressources React sont incorporées dans l'exécutable ; ADB, ses deux DLL, aapt2 et leurs notices sont joints comme ressources. Aucun Python, PySide6, serveur Node ou environnement virtuel n'est distribué. WebView2 Evergreen est requis ; l'installateur télécharge son bootstrapper s'il manque. Prévoir une connexion lors d'une première installation sans WebView2.

L’installateur se trouve dans `src-tauri/target/release/bundle/nsis/`. Le format MSI n’est plus généré pour les prochaines releases. La fonctionnalité Cargo `test-support` est réservée aux tests et ne doit pas être activée pour distribuer l'application.

Le workflow `.github/workflows/windows.yml` teste et construit sur Windows, conserve les installateurs en artefacts 14 jours et dispose uniquement de `contents: read`. Les builds de pull requests restent sans secret. Les builds internes signent les mises à jour avec le secret TAURI_SIGNING_PRIVATE_KEY. Un tag vX.Y.Z correspondant à la version du code publie automatiquement une release après tous les contrôles.

Une distribution publique peut être publiée manuellement dans les Releases GitHub après validation : tag correspondant à la version de `package.json`, Cargo et Tauri, installateur EXE du même code et fichier `SHA256SUMS.txt`. La version 2.0.1 porte uniquement sur la présentation, l’organisation du frontend et le rapport HTML imprimable. Les installateurs restent non signés. À partir de la 2.0.3, l’application recherche les releases GitHub au démarrage puis toutes les six heures et propose leur installation. La 2.0.3 doit être installée manuellement depuis une version antérieure.

## Signature Authenticode

La signature n'est pas activée : aucun certificat ni identité de signataire n'a été fourni. Pour la préparer :

1. Obtenir le certificat de signature de code de l'organisation (ou un service/HSM de signature compatible avec les exigences de son autorité).
2. Sur un runner Windows de confiance, importer le certificat dans le magasin approprié, ou installer le client du service/HSM. Ne pas exécuter cette étape sur du code de pull request non approuvé.
3. Passer à Tauri un fichier de configuration local, non versionné, contenant `bundle.windows.certificateThumbprint`, `digestAlgorithm` et `timestampUrl` réels. Pour un service distant, configurer `bundle.windows.signCommand` selon son client. Ne pas inventer l'empreinte, l'URL d'horodatage ni le nom légal du certificat.
4. Construire avec `npm run tauri -- build --config chemin/config-signature.local.json -- --locked`. La signature doit couvrir l'exécutable embarqué et les installateurs.
5. Vérifier les résultats avec `Get-AuthenticodeSignature` et l'outil de vérification du fournisseur, puis tester installation et mise à niveau sur un poste distinct.

Pour une chaîne basée sur un PFX exportable, les noms de secrets proposés sont `WINDOWS_CERTIFICATE_PFX_BASE64` et `WINDOWS_CERTIFICATE_PASSWORD`, avec l'empreinte dans une variable protégée `WINDOWS_CERTIFICATE_THUMBPRINT`. Ce sont des noms à créer, pas des identifiants existants. Un certificat matériel/service utilisera les secrets et autorisations spécifiques de son fournisseur. Détruire la copie temporaire du certificat après le job et protéger l'environnement GitHub de signature. La configuration d'auto-update Tauri n'est pas activée ; aucune clé de mise à jour n'est nécessaire.

## Outils Android

ADB 37.0.0-14910828 a été conservé : l'empreinte de son exécutable a été comparée à l'archive officielle `platform-tools_r37.0.0-win.zip`, dont `adb/NOTICE.txt` provient. aapt2 a été actualisé vers l'archive Google Maven `9.4.1-15978811` déjà épinglée par l'ancien helper Python ; son SHA-256 d'archive a été vérifié, et sa notice extraite. Version du binaire : 2.20-15978811. Les deux notices sont embarquées avec les installateurs.

Le workflow vérifie les empreintes des quatre binaires ; il ne les télécharge pas à chaque build. Leur mise à jour doit modifier simultanément le binaire, la notice et l'empreinte attendue après vérification de sa provenance. `node scripts/install-aapt2.mjs --update` permet une mise à jour explicite vers la version épinglée par le helper.

Documentation officielle : [installateurs Windows Tauri](https://v2.tauri.app/distribute/windows-installer/), [signature Windows](https://v2.tauri.app/distribute/sign/windows/), [configuration Tauri](https://v2.tauri.app/reference/config/).

## Mises à jour GitHub (2.0.3 et suivantes)

Les releases contiennent un seul installateur EXE, sa signature `.sig`, `latest.json` et `SHA256SUMS.txt`. Les deux fichiers techniques ne sont pas des installateurs supplémentaires. `scripts/prepare-release.py` génère le manifeste avec le nom exact du fichier publié. Le workflow vérifie la signature réelle et rejette un EXE modifié avant publication.

L’application vérifie `https://github.com/DwennK/Microwest-Android-Cleaner/releases/latest/download/latest.json`. Une nouvelle version est annoncée sans interrompre le travail. **Installer la mise à jour** demande confirmation, télécharge et vérifie la signature, puis lance l’installateur. Le verrou Rust partagé interdit cette opération pendant un scan, une analyse IA ou une désinstallation. Les données enregistrées restent dans le dossier utilisateur ; les résultats non enregistrés doivent être exportés. Une vérification manuelle est disponible dans les paramètres. Les builds de développement ne s’auto-installent pas.

La clé de signature initiale est sauvegardée dans `%USERPROFILE%/.tauri/microwest-android-cleaner.key` sur le poste de préparation et dans le secret GitHub `TAURI_SIGNING_PRIVATE_KEY`. Conserver cette sauvegarde hors du dépôt : perdre ou remplacer la clé empêche les versions déjà installées d’accepter de futures mises à jour. `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` est facultatif, seulement si la clé est protégée par un mot de passe.

Pour publier : mettre à jour les versions package.json/package-lock.json/Cargo.toml/Cargo.lock/tauri.conf.json, puis pousser le tag correspondant. La publication ne démarre qu’après les tests et la vérification des signatures. Les anciennes versions sans updater nécessitent une installation manuelle initiale.

### Fichiers ADB verrouillés (2.1.1)

Le serveur ADB peut rester actif après la fermeture de l’application et verrouiller `AdbWinApi.dll` et `AdbWinUsbApi.dll`. Les hooks NSIS ferment d’abord l’application, puis utilisent le gestionnaire de redémarrage Windows pour arrêter les processus qui utilisent les chemins exacts des ressources ADB de cette installation. Un serveur ADB installé ailleurs reste actif. Les DLL sont aussi contrôlées lorsque l’exécutable ADB a déjà été retiré par une ancienne désinstallation interrompue.

Ces hooks s’exécutent avant la copie des fichiers et avant leur désinstallation. Le mode interactif demande la fermeture des processus concernés ; le mode de mise à jour passive effectue cette fermeture automatiquement. Windows peut prendre quelques dizaines de secondes pour arrêter un serveur ADB. Aucun redémarrage du PC n’est normalement nécessaire.

Après un build Windows, `python -u scripts/check-installer-locks.py` compile un petit installateur avec les hooks livrés et les helpers Tauri générés. Il teste une installation neuve, une réinstallation sans ADB, une mise à jour et une désinstallation avec ADB actif, ainsi qu’une DLL verrouillée sans `adb.exe`. Les tests utilisent des dossiers temporaires et des ports ADB dédiés, et vérifient qu’un serveur provenant d’un autre dossier reste actif. Ce contrôle bloque la publication en cas d’échec.
