# Validation de la migration

## Améliorations de présentation 2.0.1 — 6 octobre 2026

- Les cinq écrans, la fiche d’application et les composants communs sont séparés. `App.tsx` passe de 2 005 à 317 lignes. Un hook commun gère le verrouillage immédiat, la progression, les erreurs et l’annulation. Les règles de diagnostic et commandes Android ne sont pas modifiées.
- TypeScript et le build Vite passent ; les 3 tests Vitest, 14 tests unitaires Rust et 4 tests d’intégration Rust passent. `cargo fmt --check` et Clippy avec `-D warnings` passent. Le nouveau test de rapport vérifie la conservation et l’échappement des données d’application, notes, raisons, avis IA et résultats de suppression.
- Parcours Playwright dans Edge avec transport Tauri simulé : paramètres, démonstration, recherche, sélection, fiche, note, validation « Conserver », export HTML, historique, progression, double clic, annulation et reprise après erreur. Les suppressions restent bloquées pour les scans fictifs, annulés et historiques ; aucune commande de suppression n’a été exécutée.
- Rendu contrôlé à 1 000 × 720 et 1 440 × 960. Les rapports HTML autonomes sont imprimés en A4, puis rendus avec Poppler pour inspection. Un rapport de stress conserve les 60 permissions longues et les 50 lignes de notes sur 5 pages, sans débordement horizontal. Les champs de métadonnées vides sont omis ; les données présentes sont conservées. Les formats CSV et plan texte restent inchangés.
- Ces contrôles ne remplacent pas les essais sur téléphone réel et poste Windows propre listés ci-dessous.

Vérifications réalisées le 29 septembre 2026 sur Windows (build système 26200), Rust 1.98.1, Node.js 24.19. Ce document distingue les vérifications automatisées, les essais sur ce poste et les validations externes.

## Référence initiale

Sur Windows avec Python 3.11 disponible : 70 tests Python réussis, 8 échecs et 10 sous-tests réussis. Deux échecs dépendent d'hypothèses Unix (permissions exécutables et recherche de HOME/aapt2). Six viennent de fichiers SQLite encore ouverts lors du nettoyage des répertoires temporaires sous Windows. La suite de référence ciblant risque/triage passe ses 40 tests et fournit 49 évaluations pour Rust.

Les 600 cas supplémentaires utilisent une graine fixe et couvrent noms, systèmes, installateurs, accès actifs, permissions, HOME, whitelist/blacklist, priorités et raisons. Les dates des tests originaux sont ramenées à « récente » ou « ancienne » pour éviter des résultats dépendant de la date d'exécution.

## Vérifications automatisées

- Rust : 13 tests unitaires et 4 tests d'intégration réussis, dont les 649 comparaisons Python/Rust. Les comparaisons vérifient score, catégorie, action et raisons.
- Parsers : appareils ADB autorisés/non autorisés/hors ligne, paquets et noms invalides, flags système, permissions demandées/accordées, HOME, libellés aapt2 et icônes raster.
- Processus : arguments structurés, annulation, timeout, arrêt effectif vérifié par absence de fichier témoin, drainage simultané stdout/stderr et délai sur les pipes hérités.
- Parcours simulé : détection → scan → règles → SQLite → relecture, interruption/déconnexion exclues des références complètes. Le transport ADB est un exécutable Rust de test ; aucun téléphone réel n'est impliqué.
- SQLite : sauvegardes, migrations historiques v1/v2, conservation des notes/réputation, comparaison, transactions et isolation des validations entre scans/appareils. Réglages JSON inconnus conservés, secrets absents des valeurs publiques et sauvegarde avant remplacement d'un fichier corrompu.
- IA : normalisation, protections locales/humaines, serveur HTTP local simulant MiniMax, repli sans response_format, nouvelle demande des verdicts absents, rejet des paquets non demandés, notes privées non envoyées. Aucun appel facturable réel.
- Rapports : échappement HTML et protection des cellules CSV ; protections moteur de désinstallation et refus des scans fictifs/incomplets/historiques.
- `cargo fmt --check`, Clippy tous targets avec `-D warnings`, compilation TypeScript/Vite et 3 tests Vitest réussis. `npm audit` : aucune vulnérabilité signalée au moment du contrôle.

## Application native et distribution

L'exécutable release a été lancé directement avec un dossier temporaire `test-results/native-runtime`, sans serveur Vite/Node et sans runtime Python. Les interactions ont été effectuées dans la fenêtre Windows :

- Connexion sans appareil : état déconnecté, scan désactivé, outils embarqués identifiés et diagnostic ADB affiché/exporté.
- Démonstration activée explicitement : trois lignes fictives, scores 90/75/0, filtres/sélection et fiche détaillée ; suppression désactivée même avec une sélection. Aucun scan fictif enregistré dans l'historique.
- Exports créés réellement : HTML, CSV, plan d'action texte et diagnostic texte. Présence et contenu des fichiers contrôlés ; aucune commande de suppression dans le plan fictif.
- Navigation vers les paramètres et l'historique vide, affichage des données et des limites de la démonstration.

La compilation Tauri release produit les installateurs Windows x64 NSIS et MSI. Les binaires Android et leurs notices sont inclus dans les ressources. L'installation des MSI/NSIS sur une machine propre et leur signature ne sont pas vérifiées ici. Le workflow GitHub Actions est configuré ; il n'a pas été exécuté sur GitHub dans cette session et aucune release n'a été publiée.

Contrôle final : nouvel exécutable démarré, diagnostic natif et paramètres accessibles ; aapt2 embarqué répond `2.20-15978811`. La table des fichiers du MSI a été lue sans installation : sept fichiers, soit l'exécutable Microwest, ADB, deux DLL, aapt2 et deux notices. Aucun runtime Python/Node n'y figure.

Empreintes des installateurs non signés produits localement (une nouvelle compilation peut les modifier) :

| Fichier | Taille | SHA-256 |
| --- | ---: | --- |
| Microwest Android Cleaner_2.0.0_x64-setup.exe | 9 396 023 octets | `2D06702FFE930DF97748A3D8BC7180F280C30F9E78F6D5C5572615FEFBC66F49` |
| Microwest Android Cleaner_2.0.0_x64_fr-FR.msi | 12 877 824 octets | `82BEA7278994489C3D9C42579CADD6EB0DFB4D082F4E9AA02DCAFB4D7DB59F66` |

ADB réel a été exécuté sur ce poste : **aucun téléphone connecté**. La détection de plusieurs appareils et des états unauthorized/offline a donc été vérifiée par transport simulé seulement.

## Essais à réaliser avant validation atelier finale

- Téléphone réel : détection multi-appareils, acceptation RSA, états offline, déconnexion pendant pull/dumpsys, reconnexion.
- Android/Samsung réel : collecte des permissions/appops, HOME pour l'utilisateur courant, noms français, APK fractionnés et icônes.
- Désinstallation : uniquement une application de test approuvée, contrôle de la boîte native, résultat sur utilisateur 0, rescanner et comparer. Aucun retrait réel n'a été autorisé ni effectué pendant la migration.
- IA : appel réel OpenAI/MiniMax avec une clé et le consentement explicite à l'envoi des métadonnées ; tests réseau simulés distincts.
- Distribution : installation/mise à niveau sur un poste Windows propre, signature Authenticode avec un certificat réel, WebView2 absent/présent.
- macOS/Linux : le moteur prévoit la recherche des outils adaptés, mais seuls les builds Windows sont configurés et doivent être annoncés comme construits ici.

La référence Python reste archivée tant que ces essais matériels ne sont pas clos. Elle n'est pas une dépendance de la nouvelle application.
