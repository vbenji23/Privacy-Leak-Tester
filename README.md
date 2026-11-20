🕵️ Testeur de fuites de confidentialité
Ce que ton navigateur dit de toi sans te demander. Un audit de confidentialité 100 % côté client qui montre tout ce qu’un site web peut apprendre sur toi en quelques millisecondes, sans cookie ni autorisation.

🔗 Démo en ligne : https://vbenji23.github.io/Privacy-Leak-Tester/

🎯 Objectif
La plupart des gens pensent qu’en supprimant leurs cookies ou en passant en navigation privée, ils deviennent anonymes. Ce projet démontre le contraire grâce au browser fingerprinting (empreinte de navigateur) : en combinant une vingtaine d’informations banales, un site peut calculer un identifiant quasi unique qui te suit de visite en visite.

Pour chaque fuite, l’outil explique pourquoi c’est un risque et comment s’en protéger.

✨ Fonctionnalités
19 tests répartis en 6 catégories (navigateur, matériel, empreinte, réseau, localisation, stockage & permissions)
Score de confidentialité sur 100 avec niveau de risque
Identifiant d’empreinte calculé à partir des attributs stables + comparaison avec la dernière analyse
Estimation de l’unicité (en bits d’entropie, inspirée de l’EFF Panopticlick / AmIUnique)
Détection de VPN : incohérence entre le fuseau horaire du navigateur et celui de l’IP
Détection de fuite WebRTC : IP locale, IP publique réelle derrière un VPN
Filtres par catégorie, export du rapport en JSON, copie du résumé
Interface réactive, thème sombre, zéro dépendance
🔬 Tests réalisés
Catégorie	Test	Technique
Navigateur	Indices utilisateur-agent et client	navigator.userAgent, userAgentData.getHighEntropyValues()
Navigateur	Langues et formats	navigator.languages, Intl
Navigateur	Préférences d’affichage	Requêtes médias CSS (, ...)prefers-color-schemepointer
Matériel	Écran & fenêtre	screen, (déduit la taille de la barre des tâches)devicePixelRatio
Matériel	CPU & RAM	hardwareConcurrency, deviceMemory
Matériel	Micros / caméras	mediaDevices.enumerateDevices()
Matériel	Batterie	API d’état de la batterie
Empreinte	Toile	Rendu d’un dessin → hash ; Détection du bruit anti-fingerprinting
Empreinte	WebGL	WEBGL_debug_renderer_info (nom exact du GPU)
Empreinte	Audio	OfflineAudioContext + compresseur dynamique
Empreinte	Polices	Mesure de largeur de texte sur 48 polices → déduit OS et logiciels
Réseau	Fuite WebRTC	RTCPeerConnection + serveur STUN, analyse des candidats ICE
Réseau	Type de connexion	API d’information réseau
Localisation	Fuseau horaire	Intl.DateTimeFormat().resolvedOptions()
Localisation	IP publique	API + comparaison fuseau / WebRTCipwho.is
Stockage	Stockage local	Cookies, localStorage, IndexedDB, quota (détection navigation privée)
Stockage	Autorisations	Permissions API
Stockage	Signaux de suivi	DNT, Contrôle mondial de la vie privée, , référent...webdriver
Stockage	Bloqueur de pubs	Élément « appât » (appât)
🔒 Confidentialité & éthique
Aucune donnée n’est envoyée à un serveur m’appartenant. Tous les calculs se font dans le navigateur.
Les deux seuls tests qui contactent un service externe (IP publique via , WebRTC via le STUN de Google) sont désactivés par défaut et nécessitent de cocher une case.ipwho.is
Le seul élément stocké est le dernier identifiant d’empreinte, dans le de ton propre navigateur, pour la comparaison entre deux analyses.localStorage
L’outil est pédagogique et défensif : il sert à prendre conscience des fuites, pas à pister qui que ce soit.
🚀 Lancer le projet
Aucune installation nécessaire :

git clone https://github.com/vbenji23/PrivacyLeakTester.git
cd PrivacyLeakTester
# Ouvrir index.html dans un navigateur
# ou lancer un petit serveur local :
python -m http.server 8000
Puis ouvre http://localhost:8000.

🧪 Expérience à faire
Lance l’analyse et note ton identifiant d’empreinte.
Ouvre le site en navigation privée et relance.
Si l’identifiant est le même, un site peut te reconnaître sans aucun cookie.
Recommence avec Brave, Firefox () ou Tor Browser et compare les scores.privacy.resistFingerprinting = true
📁 Structure
PrivacyLeakTester/
├── index.html   # Structure de la page
├── style.css    # Thème sombre « terminal »
├── app.js       # Les 19 tests, le score, l'empreinte et l'export
└── README.md
🧠 Compétences mobilisées
Connaissance des techniques de tracking et de fingerprinting utilisées par les régies publicitaires et les anti-fraudes
APIs Web avancées : Canvas, WebGL, Web Audio, WebRTC / ICE / STUN, Permissions, Stockage
Analyse réseau : candidats ICE, IP privées (RFC 1918), mDNS, détection de VPN
Développement sécurisé : échappement systématique des données affichées (anti-XSS), consentement explicite pour les requêtes externes
⚠️ Limites
L’estimation d’unicité est indicative : les attributs ne sont pas indépendants (un facteur de corrélation est appliqué).
Certains résultats varient selon le navigateur (Firefox et Safari n’exposent pas toutes les APIs).
La détection de bloqueur de pubs repose sur un élément appât et peut donner des faux négatifs.
📚 Ressources
EFF – Couvrez vos traces
AmIUnique
BrowserLeaks
