# Android Cleaner — identité visuelle

Créée le 6 octobre 2026 avec l’outil intégré ImageGen. L’icône de Microwest Whisper a servi de référence de style : carré bleu encre, matière satinée menthe et éclairage discret. Le téléphone intégré au bouclier représente le diagnostic et la protection Android. Aucun logo Android officiel n’est utilisé.

`app-icon.png` est la source originale avec transparence. `public/brand/app-icon.png` est sa déclinaison de 128 px pour la navigation et le favicon. Les fichiers `src-tauri/icons/icon.png` et `icon.ico` servent à l’application Windows et à ses installateurs.

Pour régénérer les formats, lancer `npm run tauri -- icon assets/app-icon.png --output output/cleaner-icon`, puis copier `icon.png` et `icon.ico` vers `src-tauri/icons/` et `128x128.png` vers `public/brand/app-icon.png`.

## Prompt ImageGen

Use case: logo-brand. Create ONE production-ready desktop application icon for Microwest Android Cleaner, a technician tool that inspects Android applications and identifies intrusive ads and deceptive utilities. Input image is STYLE REFERENCE ONLY: the Microwest Whisper sibling app icon. Match its premium tactile satin ceramic finish, deep ink navy rounded square and pale mint sculpture, but create an entirely different symbol appropriate for Android diagnostic protection. Center one bold minimal mint sculptural shield with a simple inset smartphone silhouette in its center; the smartphone is a clean dark rounded rectangle cutout with a tiny mint horizontal screen line. Shield and phone form ONE integrated emblem, instantly legible at 32px. Square composition. Dark ink navy (#162b38) rounded square tile occupies about 86% of canvas, consistent transparent margin. Emblem fills about 62% of tile width. Soft top-left lighting, restrained dimensional shading, smooth thick beveled mint (#b8dfd8) edges, calm professional workmanship like reference. Absolutely no letters, no text, no Android robot, no broom, no sparkle, no padlock, no micro details, no neon, no chrome, no scene or mockup. Genuine transparent background outside rounded navy tile. Deliver actual isolated PNG icon asset.
