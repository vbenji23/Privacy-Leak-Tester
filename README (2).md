# 🕵️ Privacy Leak Tester

> **Ce que ton navigateur dit de toi sans te demander.**
> Un audit de confidentialité 100 % côté client qui montre tout ce qu'un site web peut apprendre sur toi en quelques millisecondes, sans cookie ni autorisation.

🔗 **Démo en ligne :** https://vbenji23.github.io/PrivacyLeakTester/

---

## 🎯 Objectif

La plupart des gens pensent qu'en supprimant leurs cookies ou en passant en navigation privée, ils deviennent anonymes.
Ce projet démontre le contraire grâce au **browser fingerprinting** (empreinte de navigateur) : en combinant une vingtaine d'informations banales, un site peut calculer un identifiant quasi unique qui te suit de visite en visite.

Pour chaque fuite, l'outil explique **pourquoi c'est un risque** et **comment s'en protéger**.

## ✨ Fonctionnalités

- **19 tests** répartis en 6 catégories (navigateur, matériel, empreinte, réseau, localisation, stockage & permissions)
- **Score de confidentialité** sur 100 avec niveau de risque
- **Identifiant d'empreinte** calculé à partir des attributs stables + comparaison avec la dernière analyse
- **Estimation de l'unicité** (en bits d'entropie, inspirée de l'EFF Panopticlick / AmIUnique)
- **Détection de VPN** : incohérence entre le fuseau horaire du navigateur et celui de l'IP
- **Détection de fuite WebRTC** : IP locale, IP publique réelle derrière un VPN
- Filtres par catégorie, export du rapport en **JSON**, copie du résumé
- Interface responsive, thème sombre, zéro dépendance

## 🔬 Tests réalisés

| Catégorie | Test | Technique |
|---|---|---|
| Navigateur | User-Agent & Client Hints | `navigator.userAgent`, `userAgentData.getHighEntropyValues()` |
| Navigateur | Langues & formats | `navigator.languages`, `Intl` |
| Navigateur | Préférences d'affichage | Media queries CSS (`prefers-color-scheme`, `pointer`…) |
| Matériel | Écran & fenêtre | `screen`, `devicePixelRatio` (déduit la taille de la barre des tâches) |
| Matériel | CPU & RAM | `hardwareConcurrency`, `deviceMemory` |
| Matériel | Micros / caméras | `mediaDevices.enumerateDevices()` |
| Matériel | Batterie | Battery Status API |
| Empreinte | **Canvas** | Rendu d'un dessin → hash ; détection du bruit anti-fingerprinting |
| Empreinte | **WebGL** | `WEBGL_debug_renderer_info` (nom exact du GPU) |
| Empreinte | **Audio** | `OfflineAudioContext` + compresseur dynamique |
| Empreinte | **Polices** | Mesure de largeur de texte sur 48 polices → déduit OS et logiciels |
| Réseau | **Fuite WebRTC** | `RTCPeerConnection` + serveur STUN, analyse des candidats ICE |
| Réseau | Type de connexion | Network Information API |
| Localisation | Fuseau horaire | `Intl.DateTimeFormat().resolvedOptions()` |
| Localisation | **IP publique** | API `ipwho.is` + comparaison fuseau / WebRTC |
| Stockage | Stockage local | Cookies, localStorage, IndexedDB, quota (détection navigation privée) |
| Stockage | Permissions | Permissions API |
| Stockage | Signaux de suivi | DNT, Global Privacy Control, `webdriver`, referrer… |
| Stockage | Bloqueur de pubs | Élément « appât » (bait) |

## 🔒 Confidentialité & éthique

- **Aucune donnée n'est envoyée à un serveur m'appartenant.** Tous les calculs se font dans le navigateur.
- Les deux seuls tests qui contactent un service externe (IP publique via `ipwho.is`, WebRTC via le STUN de Google) sont **désactivés par défaut** et nécessitent de cocher une case.
- Le seul élément stocké est le dernier identifiant d'empreinte, dans le `localStorage` de ton propre navigateur, pour la comparaison entre deux analyses.
- L'outil est **pédagogique et défensif** : il sert à prendre conscience des fuites, pas à pister qui que ce soit.

## 🚀 Lancer le projet

Aucune installation nécessaire :

```bash
git clone https://github.com/vbenji23/PrivacyLeakTester.git
cd PrivacyLeakTester
# Ouvrir index.html dans un navigateur
# ou lancer un petit serveur local :
python -m http.server 8000
```

Puis ouvre http://localhost:8000.

## 🧪 Expérience à faire

1. Lance l'analyse et note ton **identifiant d'empreinte**.
2. Ouvre le site en **navigation privée** et relance.
3. Si l'identifiant est le même, un site peut te reconnaître **sans aucun cookie**.
4. Recommence avec Brave, Firefox (`privacy.resistFingerprinting = true`) ou Tor Browser et compare les scores.

## 📁 Structure

```
PrivacyLeakTester/
├── index.html   # Structure de la page
├── style.css    # Thème sombre « terminal »
├── app.js       # Les 19 tests, le score, l'empreinte et l'export
└── README.md
```

## 🧠 Compétences mobilisées

- Connaissance des techniques de **tracking et de fingerprinting** utilisées par les régies publicitaires et les anti-fraudes
- APIs Web avancées : Canvas, WebGL, Web Audio, WebRTC / ICE / STUN, Permissions, Storage
- Analyse réseau : candidats ICE, IP privées (RFC 1918), mDNS, détection de VPN
- Développement sécurisé : échappement systématique des données affichées (anti-XSS), consentement explicite pour les requêtes externes

## ⚠️ Limites

- L'estimation d'unicité est **indicative** : les attributs ne sont pas indépendants (un facteur de corrélation est appliqué).
- Certains résultats varient selon le navigateur (Firefox et Safari n'exposent pas toutes les APIs).
- La détection de bloqueur de pubs repose sur un élément appât et peut donner des faux négatifs.

## 📚 Ressources

- [EFF – Cover Your Tracks](https://coveryourtracks.eff.org/)
- [AmIUnique](https://amiunique.org/)
- [BrowserLeaks](https://browserleaks.com/)

---

Projet réalisé par **Benjamin Vincenti**, étudiant en cybersécurité à Guardia Cyber School.
[GitHub](https://github.com/vbenji23) · [LinkedIn](https://www.linkedin.com/in/benjamin-vincenti-835630387) · [TryHackMe](https://tryhackme.com/p/bvincenti)

Licence MIT.
