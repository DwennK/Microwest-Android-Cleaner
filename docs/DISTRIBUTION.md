# Distribution Windows

`npm ci` puis `npm run build:desktop` produisent un exécutable natif, un installateur NSIS par utilisateur et un MSI. Les ressources React sont incorporées dans l'exécutable ; ADB, ses deux DLL, aapt2 et leurs notices sont joints comme ressources. Aucun Python, PySide6, serveur Node ou environnement virtuel n'est distribué. WebView2 Evergreen est requis ; l'installateur télécharge son bootstrapper s'il manque. Prévoir une connexion lors d'une première installation sans WebView2.

Les fichiers se trouvent dans `src-tauri/target/release/bundle/nsis/` et `src-tauri/target/release/bundle/msi/`. La fonctionnalité Cargo `test-support` est réservée aux tests et ne doit pas être activée pour distribuer l'application.

Le workflow `.github/workflows/windows.yml` teste et construit sur Windows, conserve les installateurs en artefacts 14 jours et dispose uniquement de `contents: read`. Il ne crée ni release ni tag, ne publie aucun fichier publiquement et ne nécessite aucun secret pour les builds non signés.

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
