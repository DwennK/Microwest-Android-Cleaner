# Analyse atelier — règles version 3

Le score exprime une priorité de vérification, pas une probabilité d’infection.
Les décisions finales, locales et IA sont conservées séparément.

## Collecte locale

Le module APK est lu sans exécuter son code : empreinte SHA-256, références DEX
à des bibliothèques publicitaires, composants du manifeste, présence de familles
de textes alarmistes dans les ressources. L’inspection DEX est bornée à 64 Mio,
32 Mio par fichier ; le module de base seul est examiné pour les APK fractionnés.
Les limites sont enregistrées et visibles. Obfuscation, contenu téléchargé et
publicité affichée uniquement à certaines conditions peuvent échapper au scan.

Une bibliothèque publicitaire ou une erreur de stockage seule ne déclenche pas
un retrait. Un utilitaire combinant publicité et plusieurs familles alarmistes
peut être proposé au retrait, y compris sans overlay/accessibilité. Les textes
présents ne sont jamais présentés comme des comportements observés. Les cleaners
tiers relèvent d’une politique de nettoyage explicite, pas d’un diagnostic viral.

## Signatures

Sous Windows : `python scripts/install-analysis-tools.py` installe les versions
vérifiées d’apksigner et d’un JRE portable dans `tools`, sans changer PATH.
Inclure ces outils et leurs licences dans la distribution pour conserver cette
capacité. Sinon l’interface indique explicitement la vérification indisponible.
`APKSIGNER_JAR` et `JAVA_HOME` permettent d’utiliser une installation existante.

Une signature cryptographiquement valide ne prouve pas l’identité de l’éditeur.
Les références administrées par l’atelier sont dans
`data/publisher_certificates.json`, format :

```json
[
  {
    "package": "org.example.application",
    "publisher": "Éditeur vérifié",
    "signer_sha256": ["empreinte SHA-256 de 64 caractères issue d’une référence vérifiée"],
    "source": "origine et date de vérification de la référence"
  }
]
```

Aucune référence d’éditeur inventée n’est fournie. La correspondance exige le
package exact et tous les certificats signataires. Prévoir les rotations de clés
dans les références. L’identité vérifiée ne neutralise pas les autres indices.

## IA et fusion

L’IA reçoit un dictionnaire de faits identifiés, sans score local, notes ni numéro
du téléphone. Ses références doivent toutes exister pour cette application.
La justification affichée est reconstruite depuis les faits ; son texte libre
est conservé comme réponse brute dans le snapshot, sans devenir une preuve.

- Un avis étayé peut faire baisser une suspicion locale faible.
- Un avis de conservation opposé à des indices forts produit un désaccord à vérifier.
- Un retrait exige un faisceau d’indices référencés, pas seulement une confiance IA élevée.
- Les décisions humaines, listes explicitement renseignées et protections système
  restent prioritaires. Les anciennes entrées livrées par défaut dans la whitelist
  ne neutralisent plus l’analyse ; un choix explicite du technicien le peut.
- Un ancien avis IA sans références est conservé mais non appliqué.

## Historique et observation

L’ouverture d’un historique d’une ancienne version recalcule les métadonnées
disponibles et archive son payload précédent dans `analysis_revisions`, dans la
même transaction que la mise à jour. Aucun accès supplémentaire au téléphone ou
appel IA n’est déclenché. Un nouveau scan est nécessaire pour les indices APK qui
n’existaient pas dans l’ancien relevé. Les décisions et notes humaines restent conservées.

Pour identifier une publicité : la reproduire sur le téléphone puis utiliser
« Identifier l’app affichée ». Seul le package de l’activité au premier plan est
retourné ; ce constat ne prouve pas l’origine d’un overlay ou d’une notification.
Aucune application n’est lancée automatiquement, aucun texte de notification n’est lu.

## Validation

Les régressions couvrent les métadonnées des neuf apps ordinaires, des identités
renommées, des cas construits de faux utilitaires sans overlay, les désaccords IA,
les références inventées, les protections et l’archivage. Ces cas construits ne
constituent pas une mesure de rappel sur un corpus réel de logiciels indésirables.
Le corpus terrain de l’atelier devra être enrichi avec des cas confirmés et leurs
homologues légitimes ; ne pas annoncer de taux de détection sans cette mesure.
