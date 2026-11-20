/* =========================================================
   Privacy Leak Tester — app.js
   Audit de confidentialité 100 % côté client.
   Auteur : Benjamin Vincenti (vbenji23)
   ========================================================= */
'use strict';

const $ = (sel, el = document) => el.querySelector(sel);

/* ---------- Utilitaires ---------- */

// Échappe le HTML pour afficher les valeurs sans risque de XSS
function esc(v) {
  return String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Hash rapide non cryptographique (cyrb53) — suffisant pour un identifiant d'empreinte
function cyrb53(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, '0');
}

const withTimeout = (promise, ms, fallback) =>
  Promise.race([promise, new Promise(resolve => setTimeout(() => resolve(fallback), ms))]);

const sleep = ms => new Promise(r => setTimeout(r, ms));

const isPrivateIP = ip =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|fe80:|fc|fd)/i.test(ip);

/* ---------- Données ---------- */

const CATS = {
  nav: 'Navigateur',
  hw: 'Matériel',
  fp: 'Empreinte',
  net: 'Réseau',
  loc: 'Localisation',
  perm: 'Stockage & permissions'
};

const RISK_LABEL = { high: 'élevé', med: 'moyen', low: 'faible' };

const STATUS_LABEL = {
  pending: 'EN ATTENTE',
  running: 'ANALYSE…',
  leak: 'EXPOSÉ',
  partial: 'PARTIEL',
  safe: 'PROTÉGÉ',
  na: 'NON TESTÉ'
};

const FONTS = [
  'Arial', 'Arial Black', 'Calibri', 'Cambria', 'Candara', 'Comic Sans MS', 'Consolas', 'Constantia',
  'Corbel', 'Courier New', 'Georgia', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
  'Palatino Linotype', 'Segoe UI', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana',
  'Helvetica', 'Helvetica Neue', 'Menlo', 'Monaco', 'Gill Sans', 'Futura', 'Avenir', 'Optima',
  'Didot', 'American Typewriter', 'Ubuntu', 'DejaVu Sans', 'Liberation Sans', 'Noto Sans',
  'Cantarell', 'Roboto', 'Open Sans', 'Fira Code', 'Source Code Pro', 'JetBrains Mono',
  'Cascadia Code', 'Garamond', 'Bookman Old Style', 'Century Gothic', 'Franklin Gothic Medium',
  'MS Gothic', 'SimSun', 'Wingdings'
];

// État global de l'analyse
const state = { results: {}, browserTz: null, webrtcPublic: [], filter: 'all' };

/* =========================================================
   LES TESTS
   Chaque test renvoie : { status, rows: [[label, valeur]], note?, warn?, preview?, fp? }
   - status : leak | partial | safe | na
   - fp     : chaîne stable qui entre dans l'empreinte globale
   - bits   : entropie approximative (sources : EFF Panopticlick / AmIUnique)
   ========================================================= */

const TESTS = [
  {
    id: 'ua', cat: 'nav', title: 'User-Agent & version du navigateur', risk: 'med', bits: 10,
    why: "Le User-Agent annonce ton navigateur, sa version exacte et ton système. Les « Client Hints » de Chrome peuvent même révéler la version précise de ton OS et ton architecture.",
    protect: "Garde ton navigateur à jour (la version la plus répandue te noie dans la masse). Tor Browser et Firefox (resistFingerprinting) uniformisent ces valeurs.",
    async run() {
      const n = navigator;
      const rows = [
        ['User-Agent', n.userAgent],
        ['Plateforme', n.platform || '—'],
        ['Éditeur', n.vendor || '—']
      ];
      if (n.userAgentData) {
        rows.push(['Marques (Client Hints)', n.userAgentData.brands.map(b => `${b.brand} ${b.version}`).join(', ')]);
        rows.push(['Appareil mobile', n.userAgentData.mobile ? 'oui' : 'non']);
        try {
          const h = await n.userAgentData.getHighEntropyValues(['platformVersion', 'architecture', 'bitness', 'model', 'fullVersionList']);
          rows.push(['Version du système', h.platformVersion || '—']);
          rows.push(['Architecture', (h.architecture || '—') + (h.bitness ? ` (${h.bitness} bits)` : '')]);
          if (h.model) rows.push(['Modèle', h.model]);
          if (h.fullVersionList) rows.push(['Versions complètes', h.fullVersionList.map(b => `${b.brand} ${b.version}`).join(', ')]);
        } catch (e) { /* refusé par le navigateur */ }
      }
      return { status: 'leak', rows, fp: n.userAgent };
    }
  },

  {
    id: 'lang', cat: 'nav', title: 'Langues & formats régionaux', risk: 'low', bits: 5,
    why: "La liste de tes langues (et leur ordre) est souvent très personnelle : « fr-FR, en-US, it » ne ressemble pas à « fr-FR, en ».",
    protect: "Ne garde qu'une ou deux langues dans les réglages du navigateur.",
    run() {
      const n = navigator;
      const loc = Intl.DateTimeFormat().resolvedOptions().locale;
      const d = new Date(2026, 0, 31, 14, 5);
      return {
        status: 'leak',
        rows: [
          ['Langue principale', n.language],
          ['Langues acceptées', (n.languages || []).join(', ')],
          ['Locale Intl', loc],
          ['Format de date', d.toLocaleString()],
          ['Format de nombre', (1234567.891).toLocaleString()]
        ],
        fp: (n.languages || []).join(',') + '|' + loc
      };
    }
  },

  {
    id: 'tz', cat: 'loc', title: 'Fuseau horaire', risk: 'med', bits: 3,
    why: "Ton fuseau horaire révèle ta région, même si tu utilises un VPN : il vient de ton système, pas de ton IP.",
    protect: "Tor Browser force le fuseau UTC. Sinon, garde en tête qu'un VPN ne cache pas cette info.",
    run() {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      state.browserTz = tz;
      const off = -new Date().getTimezoneOffset();
      const sign = off >= 0 ? '+' : '-';
      const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, '0');
      const mm = String(Math.abs(off) % 60).padStart(2, '0');
      return {
        status: 'leak',
        rows: [
          ['Fuseau horaire', tz],
          ['Décalage', `UTC${sign}${hh}:${mm}`],
          ['Heure locale', new Date().toLocaleTimeString()]
        ],
        fp: tz
      };
    }
  },

  {
    id: 'screen', cat: 'hw', title: 'Écran & fenêtre', risk: 'med', bits: 4.8,
    why: "Résolution, zone disponible et ratio de pixels décrivent précisément ton écran. La différence entre écran et zone disponible trahit même la taille de ta barre des tâches.",
    protect: "Firefox (resistFingerprinting) et Tor arrondissent la taille de la fenêtre (letterboxing).",
    run() {
      const s = screen;
      const bar = s.height - s.availHeight;
      return {
        status: 'leak',
        rows: [
          ['Résolution écran', `${s.width} × ${s.height}`],
          ['Zone disponible', `${s.availWidth} × ${s.availHeight}`],
          ['Taille de la fenêtre', `${innerWidth} × ${innerHeight}`],
          ['Profondeur de couleur', `${s.colorDepth} bits`],
          ['Ratio de pixels', devicePixelRatio],
          ['Orientation', (s.orientation && s.orientation.type) || '—']
        ],
        note: bar > 0 ? `Il manque ${bar}px entre l'écran et la zone disponible : c'est la hauteur de ta barre des tâches / du dock.` : null,
        fp: [s.width, s.height, s.availWidth, s.availHeight, s.colorDepth, devicePixelRatio].join('x')
      };
    }
  },

  {
    id: 'hw', cat: 'hw', title: 'Processeur & mémoire', risk: 'med', bits: 3.5,
    why: "Le nombre de cœurs et la quantité de RAM (arrondie) aident à distinguer un PC gamer d'un portable d'entrée de gamme.",
    protect: "Les navigateurs anti-empreinte renvoient des valeurs fixes (ex. 2 ou 4 cœurs).",
    run() {
      const n = navigator;
      return {
        status: 'leak',
        rows: [
          ['Cœurs CPU (logiques)', n.hardwareConcurrency ?? 'masqué'],
          ['Mémoire RAM', n.deviceMemory ? `${n.deviceMemory} Go (valeur arrondie)` : 'masquée'],
          ['Points tactiles max', n.maxTouchPoints ?? 0]
        ],
        fp: [n.hardwareConcurrency, n.deviceMemory, n.maxTouchPoints].join('|')
      };
    }
  },

  {
    id: 'canvas', cat: 'fp', title: 'Empreinte Canvas', risk: 'high', bits: 8,
    why: "Le site dessine un texte et des formes invisibles. Le rendu au pixel près dépend de ton GPU, de ton pilote, de ton OS et de l'anticrénelage : son hash devient un identifiant quasi unique.",
    protect: "Brave et Firefox (resistFingerprinting) ajoutent du bruit ou bloquent la lecture du canvas. L'extension CanvasBlocker fait de même.",
    run() {
      const draw = () => {
        const c = document.createElement('canvas');
        c.width = 300; c.height = 64;
        const x = c.getContext('2d');
        if (!x) return null;
        x.textBaseline = 'top';
        x.font = "16px 'Arial'";
        x.fillStyle = '#f60';
        x.fillRect(130, 4, 90, 28);
        x.fillStyle = '#069';
        x.fillText('PrivacyLeak 😃 <canvas> 1.0', 4, 8);
        x.fillStyle = 'rgba(102, 204, 0, 0.7)';
        x.font = "18px 'Times New Roman'";
        x.fillText('Cwm fjordbank glyphs vext quiz', 6, 34);
        const g = x.createLinearGradient(0, 0, 300, 0);
        g.addColorStop(0, 'red'); g.addColorStop(1, 'blue');
        x.fillStyle = g;
        x.beginPath(); x.arc(270, 32, 22, 0, Math.PI * 2); x.fill();
        return c.toDataURL();
      };
      const a = draw();
      if (!a) return { status: 'safe', rows: [['Canvas', 'indisponible']] };
      const b = draw();
      const h = cyrb53(a);
      if (a !== b) {
        return {
          status: 'safe',
          rows: [['Empreinte', 'différente à chaque lecture'], ['Hash (1er tirage)', h]],
          note: "Ton navigateur ajoute du bruit aléatoire au canvas : l'empreinte est inutilisable. Bonne protection !"
        };
      }
      return {
        status: 'leak',
        rows: [['Hash du rendu', h], ['Taille des données', `${a.length} caractères`]],
        preview: a,
        fp: h
      };
    }
  },

  {
    id: 'webgl', cat: 'fp', title: 'Carte graphique (WebGL)', risk: 'high', bits: 7,
    why: "WebGL donne souvent le nom exact de ta carte graphique et de son pilote, plus des dizaines de paramètres techniques.",
    protect: "Firefox (resistFingerprinting) et Tor masquent le nom du GPU. Tu peux aussi désactiver WebGL (webgl.disabled dans Firefox).",
    run() {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { status: 'safe', rows: [['WebGL', 'désactivé ou indisponible']] };
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      const vendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      const renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      const exts = gl.getSupportedExtensions() || [];
      const maxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      const masked = !ext || /^(Mozilla|WebKit|Google Inc\.?)$/i.test(String(renderer));
      return {
        status: masked ? 'partial' : 'leak',
        rows: [
          ['Fabricant GPU', vendor],
          ['Carte graphique', renderer],
          ['Version', gl.getParameter(gl.VERSION)],
          ['Langage shader', gl.getParameter(gl.SHADING_LANGUAGE_VERSION)],
          ['Taille max. texture', maxTex],
          ['Extensions supportées', exts.length]
        ],
        note: masked ? 'Le nom réel du GPU est masqué, mais les paramètres techniques restent lisibles.' : null,
        fp: [vendor, renderer, maxTex, exts.join(',')].join('|')
      };
    }
  },

  {
    id: 'audio', cat: 'fp', title: 'Empreinte audio', risk: 'med', bits: 5,
    why: "Le site génère un son inaudible et le fait passer dans un compresseur. Le résultat numérique varie légèrement selon ton matériel et ton système : une autre empreinte, sans aucun micro.",
    protect: "Brave randomise l'empreinte audio ; Firefox (resistFingerprinting) la limite.",
    async run() {
      const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AC) return { status: 'safe', rows: [['Audio', 'API indisponible']] };
      const ctx = new AC(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
      comp.attack.value = 0; comp.release.value = 0.25;
      osc.connect(comp); comp.connect(ctx.destination);
      osc.start(0);
      const buf = await ctx.startRendering();
      const data = buf.getChannelData(0);
      let sum = 0;
      for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
      const val = sum.toString();
      return {
        status: 'leak',
        rows: [['Valeur calculée', val], ['Hash', cyrb53(val)]],
        fp: val
      };
    }
  },

  {
    id: 'fonts', cat: 'fp', title: 'Polices installées', risk: 'high', bits: 13,
    why: "La liste de tes polices dépend de ton OS et des logiciels installés (Office, Adobe, outils de dev…). C'est l'un des attributs les plus identifiants.",
    protect: "Firefox (resistFingerprinting) et Tor n'exposent que les polices de base du système.",
    run() {
      const c = document.createElement('canvas').getContext('2d');
      const txt = 'mmmmmmmmmmlli1WQ@#';
      const bases = ['monospace', 'sans-serif', 'serif'];
      const width = f => { c.font = f; return c.measureText(txt).width; };
      const baseW = bases.map(b => width(`72px ${b}`));
      const found = FONTS.filter(f => bases.some((b, i) => width(`72px "${f}", ${b}`) !== baseW[i]));

      const hints = [];
      if (found.includes('Segoe UI')) hints.push('Windows');
      if (found.includes('Menlo') || found.includes('Helvetica Neue')) hints.push('macOS');
      if (found.includes('Ubuntu') || found.includes('DejaVu Sans') || found.includes('Cantarell')) hints.push('Linux');
      if (found.includes('Calibri') || found.includes('Cambria')) hints.push('Microsoft Office');
      if (found.some(f => ['Fira Code', 'JetBrains Mono', 'Cascadia Code', 'Source Code Pro'].includes(f))) hints.push('outils de développeur');

      return {
        status: found.length ? 'leak' : 'safe',
        rows: [
          ['Polices détectées', `${found.length} / ${FONTS.length} testées`],
          ['Liste', found.join(', ') || 'aucune']
        ],
        note: hints.length ? `Ces polices suggèrent : ${hints.join(', ')}.` : null,
        fp: found.join(',')
      };
    }
  },

  {
    id: 'prefs', cat: 'nav', title: "Préférences d'affichage", risk: 'low', bits: 2,
    why: "Thème sombre, animations réduites, type de pointeur… Les « media queries » CSS révèlent tes réglages d'accessibilité et ton type d'appareil, même sans JavaScript.",
    protect: "Difficile à bloquer : c'est une petite fuite, mais elle s'ajoute aux autres.",
    run() {
      const m = q => matchMedia(q).matches;
      return {
        status: 'leak',
        rows: [
          ['Thème', m('(prefers-color-scheme: dark)') ? 'sombre' : 'clair'],
          ['Animations réduites', m('(prefers-reduced-motion: reduce)') ? 'oui' : 'non'],
          ['Contraste élevé', m('(prefers-contrast: more)') ? 'oui' : 'non'],
          ['Pointeur', m('(pointer: coarse)') ? 'tactile' : m('(pointer: fine)') ? 'souris / pavé tactile' : 'aucun'],
          ['Survol possible', m('(hover: hover)') ? 'oui' : 'non'],
          ['Gamut couleur', m('(color-gamut: p3)') ? 'P3 (écran haut de gamme)' : 'sRGB']
        ]
      };
    }
  },

  {
    id: 'devices', cat: 'hw', title: 'Micros, caméras & haut-parleurs', risk: 'med', bits: 2,
    why: "Sans rien demander, un site peut compter tes périphériques audio et vidéo. Si tu as déjà donné la permission caméra/micro, il voit aussi leurs noms exacts (ex. « Logitech C920 »).",
    protect: "Révoque les permissions caméra/micro des sites dont tu n'as plus besoin.",
    async run() {
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
        return { status: 'safe', rows: [['Périphériques', 'API indisponible']] };
      }
      const d = await navigator.mediaDevices.enumerateDevices();
      const count = k => d.filter(x => x.kind === k).length;
      const labels = d.filter(x => x.label).map(x => x.label);
      return {
        status: d.length ? (labels.length ? 'leak' : 'partial') : 'safe',
        rows: [
          ['Micros', count('audioinput')],
          ['Haut-parleurs', count('audiooutput')],
          ['Caméras', count('videoinput')],
          ['Noms visibles', labels.length ? labels.join(', ') : 'non (masqués sans permission)']
        ]
      };
    }
  },

  {
    id: 'battery', cat: 'hw', title: 'Batterie', risk: 'low', bits: 1,
    why: "Niveau de batterie et temps restant changent lentement : des chercheurs ont montré qu'ils permettaient de relier deux visites (même en navigation privée) en quelques secondes.",
    protect: "Firefox et Safari ont supprimé cette API. Chrome l'expose encore.",
    async run() {
      if (!navigator.getBattery) return { status: 'safe', rows: [['API Batterie', 'non exposée par ton navigateur 👍']] };
      const b = await navigator.getBattery();
      return {
        status: 'leak',
        rows: [
          ['Niveau', `${Math.round(b.level * 100)} %`],
          ['En charge', b.charging ? 'oui' : 'non'],
          ['Temps restant', b.dischargingTime === Infinity ? '—' : `${Math.round(b.dischargingTime / 60)} min`]
        ]
      };
    }
  },

  {
    id: 'conn', cat: 'net', title: 'Type de connexion', risk: 'low', bits: 1,
    why: "L'API Network Information donne une estimation de ton débit et de ta latence : elle aide à deviner si tu es en 4G, en Wi-Fi ou en fibre.",
    protect: "Firefox et Safari ne l'exposent pas.",
    run() {
      const c = navigator.connection;
      if (!c) return { status: 'safe', rows: [['Network Information API', 'non exposée 👍']] };
      return {
        status: 'leak',
        rows: [
          ['Type estimé', c.effectiveType || '—'],
          ['Débit estimé', c.downlink != null ? `${c.downlink} Mb/s` : '—'],
          ['Latence (RTT)', c.rtt != null ? `${c.rtt} ms` : '—'],
          ['Économie de données', c.saveData ? 'oui' : 'non']
        ]
      };
    }
  },

  {
    id: 'storage', cat: 'perm', title: 'Stockage local', risk: 'low', bits: 1,
    why: "Cookies, localStorage et IndexedDB permettent de stocker un identifiant. Le quota disponible est calculé à partir de l'espace disque libre, et un quota anormalement bas peut trahir la navigation privée.",
    protect: "Supprime les cookies à la fermeture du navigateur et utilise l'isolation des cookies (Firefox Total Cookie Protection).",
    async run() {
      const test = fn => { try { fn(); return 'disponible'; } catch (e) { return 'bloqué'; } };
      const rows = [
        ['Cookies', navigator.cookieEnabled ? 'activés' : 'désactivés'],
        ['localStorage', test(() => { localStorage.setItem('_plt', '1'); localStorage.removeItem('_plt'); })],
        ['sessionStorage', test(() => { sessionStorage.setItem('_plt', '1'); sessionStorage.removeItem('_plt'); })],
        ['IndexedDB', window.indexedDB ? 'disponible' : 'indisponible']
      ];
      let note = null;
      if (navigator.storage && navigator.storage.estimate) {
        const e = await navigator.storage.estimate();
        const gb = e.quota / 1024 ** 3;
        rows.push(['Quota de stockage', gb >= 1 ? `${gb.toFixed(1)} Go` : `${(e.quota / 1024 ** 2).toFixed(0)} Mo`]);
        note = gb < 1.2
          ? 'Quota très faible : cela pourrait indiquer une navigation privée, et un site peut le détecter.'
          : "Le quota dépend de l'espace libre sur ton disque : il donne une idée de sa taille.";
      }
      return { status: 'leak', rows, note };
    }
  },

  {
    id: 'perms', cat: 'perm', title: 'Permissions accordées', risk: 'low', bits: 1,
    why: "Un site peut vérifier silencieusement quelles permissions tu lui as accordées (localisation, caméra, notifications…) avant même de te les demander.",
    protect: "Fais régulièrement le ménage dans les permissions des sites (paramètres du navigateur → Confidentialité).",
    async run() {
      if (!navigator.permissions) return { status: 'safe', rows: [['API Permissions', 'indisponible']] };
      const list = [
        ['geolocation', 'Géolocalisation'], ['notifications', 'Notifications'],
        ['camera', 'Caméra'], ['microphone', 'Micro'], ['clipboard-read', 'Presse-papiers']
      ];
      const fr = { granted: '✅ autorisé', denied: '⛔ refusé', prompt: '❔ demandera' };
      const rows = [];
      let granted = 0;
      for (const [name, label] of list) {
        try {
          const r = await navigator.permissions.query({ name });
          rows.push([label, fr[r.state] || r.state]);
          if (r.state === 'granted') granted++;
        } catch (e) {
          rows.push([label, 'non supporté']);
        }
      }
      return {
        status: granted ? 'leak' : 'partial',
        rows,
        note: granted
          ? `${granted} permission(s) déjà accordée(s) à ce site.`
          : "Aucune permission accordée, mais l'état de tes réglages reste lisible."
      };
    }
  },

  {
    id: 'signals', cat: 'perm', title: 'Signaux de suivi & automatisation', risk: 'low', bits: 1,
    why: "Do Not Track, Global Privacy Control, plugins, historique de l'onglet, page précédente… Ce sont de petites infos, mais elles s'additionnent.",
    protect: "Active Global Privacy Control (GPC) : en Europe et en Californie, il a une vraie valeur juridique, contrairement à Do Not Track.",
    run() {
      const n = navigator;
      const gpc = n.globalPrivacyControl;
      return {
        status: 'partial',
        rows: [
          ['Do Not Track', n.doNotTrack === '1' ? 'activé' : 'désactivé'],
          ['Global Privacy Control', gpc === true ? 'activé' : gpc === false ? 'désactivé' : 'non supporté'],
          ['Navigateur automatisé (webdriver)', n.webdriver ? 'oui (robot ?)' : 'non'],
          ['Lecteur PDF intégré', n.pdfViewerEnabled ? 'oui' : 'non'],
          ['Plugins', n.plugins ? n.plugins.length : 0],
          ["Pages dans l'historique de l'onglet", history.length],
          ['Page précédente (referrer)', document.referrer || 'aucune']
        ],
        note: "Ironie : activer Do Not Track rend ton navigateur un peu plus reconnaissable, car peu de gens l'activent."
      };
    }
  },

  {
    id: 'adblock', cat: 'perm', title: 'Bloqueur de publicités', risk: 'low', bits: 1,
    why: "Sans bloqueur, les scripts publicitaires et les traqueurs tiers se chargent librement et peuvent te suivre de site en site.",
    protect: "Installe uBlock Origin (le plus efficace) ou utilise Brave.",
    async run() {
      const bait = document.createElement('div');
      bait.className = 'adsbox ad-banner adsbygoogle pub_300x250 text-ad';
      bait.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:300px;height:250px;';
      bait.innerHTML = '&nbsp;';
      document.body.appendChild(bait);
      await sleep(200);
      const cs = getComputedStyle(bait);
      const blocked = !bait.isConnected || bait.offsetHeight === 0 || cs.display === 'none' || cs.visibility === 'hidden';
      bait.remove();
      return blocked
        ? { status: 'safe', rows: [['Bloqueur de pubs', 'détecté ✅']], note: 'Bonne protection contre les traqueurs, mais un site peut voir que tu en utilises un.' }
        : { status: 'leak', rows: [['Bloqueur de pubs', 'non détecté']], note: 'Les scripts publicitaires et les traqueurs tiers peuvent se charger librement.' };
    }
  },

  {
    id: 'webrtc', cat: 'net', title: 'Fuite WebRTC', risk: 'high', bits: 3, network: true,
    why: "WebRTC contacte un serveur STUN pour découvrir tes adresses IP. Il peut révéler ton IP locale (192.168.x.x) et ton IP publique réelle, même si tu passes par un VPN mal configuré.",
    protect: "Utilise un VPN avec protection WebRTC, uBlock Origin (option « Empêcher la fuite des adresses IP locales via WebRTC ») ou désactive WebRTC (media.peerconnection.enabled = false dans Firefox).",
    async run() {
      const PC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
      if (!PC) return { status: 'safe', rows: [['WebRTC', 'désactivé 👍']] };

      const ips = new Map();   // ip -> type de candidat (host, srflx…)
      const mdns = new Set();  // adresses masquées en .local
      const pc = new PC({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      pc.createDataChannel('plt');

      const done = new Promise(resolve => {
        pc.onicecandidate = e => {
          if (!e.candidate) return resolve();
          // Format : "candidate:<id> 1 udp <prio> <IP> <port> typ <type> ..."
          const parts = e.candidate.candidate.split(' ');
          const addr = parts[4], type = parts[7];
          if (!addr) return;
          if (addr.endsWith('.local')) mdns.add(addr);
          else if (!ips.has(addr)) ips.set(addr, type);
        };
        setTimeout(resolve, 4000);
      });
      await pc.setLocalDescription(await pc.createOffer());
      await done;
      pc.close();

      const local = [...ips].filter(([ip]) => isPrivateIP(ip)).map(([ip]) => ip);
      const pub = [...ips].filter(([ip]) => !isPrivateIP(ip)).map(([ip]) => ip);
      state.webrtcPublic = pub;

      const rows = [
        ['IP locales', local.join(', ') || 'aucune'],
        ['IP publique (via STUN)', pub.join(', ') || 'aucune'],
        ['Adresses masquées (mDNS)', mdns.size ? `${mdns.size} (ex. ${[...mdns][0].slice(0, 13)}….local)` : 'aucune']
      ];

      if (local.length) {
        return { status: 'leak', rows, warn: true, note: "Ton IP locale fuit : elle révèle la structure de ton réseau domestique ou d'entreprise." };
      }
      if (pub.length) {
        return { status: 'leak', rows, note: 'WebRTC révèle ton IP publique sans passer par une requête HTTP classique. Compare-la avec la carte « IP publique ».' };
      }
      if (mdns.size) {
        return { status: 'partial', rows, note: "Ton IP locale est masquée par une adresse aléatoire en .local : c'est la protection par défaut des navigateurs récents." };
      }
      return { status: 'safe', rows, note: 'Aucune adresse IP récupérée via WebRTC.' };
    }
  },

  {
    id: 'ip', cat: 'loc', title: 'IP publique & géolocalisation', risk: 'high', bits: 4, network: true,
    why: "Ton IP publique donne ton fournisseur d'accès et une localisation approximative (ville). C'est la première chose que voit n'importe quel serveur.",
    protect: "Un VPN ou Tor masque ton IP. Attention : si ton fuseau horaire ne correspond pas au pays de l'IP, un site peut deviner que tu utilises un VPN.",
    async run() {
      let data = null;
      try {
        const r = await fetch('https://ipwho.is/', { cache: 'no-store' });
        data = await r.json();
      } catch (e) { /* service bloqué */ }

      if (!data || data.success === false) {
        return { status: 'na', rows: [['Statut', 'service de géolocalisation injoignable (bloqué par une extension ?)']] };
      }

      const rows = [
        ['Adresse IP', data.ip],
        ["Fournisseur d'accès", (data.connection && (data.connection.isp || data.connection.org)) || '—'],
        ['Ville', data.city || '—'],
        ['Région', data.region || '—'],
        ['Pays', `${data.country || '—'} ${data.flag && data.flag.emoji ? data.flag.emoji : ''}`],
        ["Fuseau de l'IP", (data.timezone && data.timezone.id) || '—']
      ];

      const notes = [];
      let warn = false;
      const ipTz = data.timezone && data.timezone.id;
      if (ipTz && state.browserTz && ipTz !== state.browserTz) {
        notes.push(`Ton navigateur est réglé sur « ${state.browserTz} » mais ton IP est située sur « ${ipTz} » : un site peut deviner que tu utilises un VPN ou un proxy.`);
      }
      const sameFamily = state.webrtcPublic.filter(ip => ip.includes(':') === String(data.ip).includes(':'));
      if (sameFamily.length && !sameFamily.includes(data.ip)) {
        warn = true;
        notes.push(`⚠️ WebRTC révèle une autre IP publique (${sameFamily.join(', ')}) que celle vue par les sites (${data.ip}). Si tu es sous VPN, ta vraie IP fuit !`);
      }
      return { status: 'leak', rows, note: notes.join(' ') || null, warn };
    }
  }
];

/* =========================================================
   AFFICHAGE
   ========================================================= */

function cardHTML(t, res) {
  const status = res.status;
  const rows = (res.rows || [])
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`)
    .join('');
  const body = status === 'running'
    ? '<p><span class="spinner"></span> Analyse en cours…</p>'
    : status === 'pending'
      ? '<p class="risk">En attente…</p>'
      : `<table class="rows">${rows}</table>`;
  const preview = res.preview ? `<img class="preview" src="${res.preview}" alt="Rendu canvas utilisé pour l'empreinte">` : '';
  const note = res.note ? `<p class="note${res.warn ? ' warn' : ''}">${esc(res.note)}</p>` : '';

  return `
  <article class="card status-${status}" id="card-${t.id}" data-cat="${t.cat}">
    <div class="card-head">
      <div>
        <div class="card-cat">${esc(CATS[t.cat])}${t.network ? ' · requête externe' : ''}</div>
        <h3>${esc(t.title)}</h3>
      </div>
      <span class="badge">${STATUS_LABEL[status]}</span>
    </div>
    <div class="risk">Risque : <b>${RISK_LABEL[t.risk]}</b></div>
    ${body}
    ${preview}
    ${note}
    <details>
      <summary>Pourquoi c'est un risque ? Comment se protéger ?</summary>
      <p><b>Risque :</b> ${esc(t.why)}</p>
      <p><b>Se protéger :</b> ${esc(t.protect)}</p>
    </details>
  </article>`;
}

function setCard(t, res) {
  const el = document.getElementById(`card-${t.id}`);
  if (el) el.outerHTML = cardHTML(t, res);
  applyFilter();
}

function renderFilters() {
  const btns = [['all', 'Tout'], ...Object.entries(CATS), ['leak', '🔴 Exposés seulement']];
  $('#filters').innerHTML = btns
    .map(([k, label]) => `<button class="filter${state.filter === k ? ' active' : ''}" data-f="${k}">${esc(label)}</button>`)
    .join('');
  $('#filters').querySelectorAll('.filter').forEach(b => b.addEventListener('click', () => {
    state.filter = b.dataset.f;
    renderFilters();
    applyFilter();
  }));
}

function applyFilter() {
  document.querySelectorAll('.card').forEach(c => {
    const f = state.filter;
    const show = f === 'all' || (f === 'leak' ? c.classList.contains('status-leak') : c.dataset.cat === f);
    c.classList.toggle('hidden', !show);
  });
}

/* ---------- Score & empreinte globale ---------- */

function computeSummary() {
  const tested = TESTS.map(t => [t, state.results[t.id]]).filter(([, r]) => r && r.status !== 'na');
  const W = { high: 10, med: 5, low: 2 };
  let score = 100, bits = 0, leaks = 0;
  for (const [t, r] of tested) {
    if (r.status === 'leak') { score -= W[t.risk]; bits += t.bits; leaks++; }
    else if (r.status === 'partial') { score -= W[t.risk] / 2; bits += t.bits / 2; }
  }
  score = Math.max(0, Math.round(score));

  // Les attributs ne sont pas indépendants : on applique un facteur de corrélation (estimation)
  const effBits = bits * 0.6;

  const fpString = TESTS.map(t => state.results[t.id] && state.results[t.id].fp).filter(Boolean).join('||');
  const fpId = cyrb53(fpString).slice(0, 12).toUpperCase();

  return { score, leaks, tested: tested.length, effBits, fpId };
}

function uniquenessText(bits) {
  if (bits >= 33) return { main: 'Probablement unique', sub: "Ton empreinte te distingue sans doute de tous les internautes (8 milliards ≈ 2³³)." };
  const n = Math.round(2 ** bits);
  return { main: `≈ 1 sur ${n.toLocaleString('fr-FR')}`, sub: 'navigateurs partageraient la même empreinte que toi.' };
}

function renderSummary() {
  const s = computeSummary();
  const u = uniquenessText(s.effBits);
  const color = s.score < 30 ? 'var(--red)' : s.score < 60 ? 'var(--orange)' : 'var(--accent)';
  const label = s.score < 30 ? 'Très traçable' : s.score < 60 ? 'Traçable' : s.score < 80 ? 'Plutôt protégé' : 'Bien protégé';

  // Comparaison avec la dernière visite (stockée en local, uniquement sur ton appareil)
  let visit = 'Première analyse sur ce navigateur.';
  try {
    const last = JSON.parse(localStorage.getItem('plt_last') || 'null');
    if (last) {
      const when = new Date(last.date).toLocaleString('fr-FR');
      visit = last.id === s.fpId
        ? `Identique à ton analyse du ${when} : ton empreinte est stable, un site peut te reconnaître.`
        : `Différente de ton analyse du ${when} (${last.id}).`;
    }
    localStorage.setItem('plt_last', JSON.stringify({ id: s.fpId, date: Date.now() }));
  } catch (e) { /* stockage bloqué */ }

  state.summary = { ...s, label, uniqueness: u.main };

  $('#summary').innerHTML = `
    <div class="ring" style="--p:${s.score};--c:${color}">
      <div class="ring-inner">
        <div class="ring-score" style="color:${color}">${s.score}</div>
        <div class="ring-label">/ 100<br>${label}</div>
      </div>
    </div>
    <div class="stats">
      <div class="stat">
        <div class="stat-title">Identifiant d'empreinte</div>
        <div class="stat-value">${s.fpId}</div>
        <div class="stat-sub">${esc(visit)}</div>
      </div>
      <div class="stat">
        <div class="stat-title">Données exposées</div>
        <div class="stat-value">${s.leaks} / ${s.tested}</div>
        <div class="stat-sub">tests où une information fuit entièrement.</div>
      </div>
      <div class="stat">
        <div class="stat-title">Unicité estimée</div>
        <div class="stat-value">${esc(u.main)}</div>
        <div class="stat-sub">${esc(u.sub)} <em>(estimation indicative)</em></div>
      </div>
    </div>`;
  $('#summary').classList.remove('hidden');
}

/* =========================================================
   LANCEMENT DE L'ANALYSE
   ========================================================= */

async function runAll() {
  const btn = $('#runBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Analyse en cours…';
  state.results = {};
  state.webrtcPublic = [];

  $('#results').classList.remove('hidden');
  $('#summary').classList.add('hidden');
  renderFilters();
  $('#grid').innerHTML = TESTS.map(t => cardHTML(t, { status: 'pending' })).join('');
  $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });

  const consent = $('#netConsent').checked;

  // Les tests sont lancés un par un : l'ordre compte (WebRTC avant IP, fuseau avant IP)
  for (const t of TESTS) {
    setCard(t, { status: 'running' });
    let res;
    if (t.network && !consent) {
      res = {
        status: 'na',
        rows: [['Statut', 'test réseau non autorisé']],
        note: 'Coche la case « tests réseau » en haut de la page puis relance pour voir ce test.'
      };
    } else {
      try {
        res = await withTimeout(
          Promise.resolve().then(() => t.run()),
          7000,
          { status: 'na', rows: [['Statut', 'délai dépassé']] }
        );
      } catch (e) {
        res = { status: 'na', rows: [['Erreur', e.message || String(e)]] };
      }
    }
    state.results[t.id] = res;
    setCard(t, res);
    await sleep(60); // petite pause pour l'effet visuel
  }

  renderSummary();
  $('#summary').scrollIntoView({ behavior: 'smooth', block: 'start' });
  btn.disabled = false;
  btn.textContent = "↻ Relancer l'analyse";
}

/* ---------- Export ---------- */

function buildReport() {
  return {
    outil: 'Privacy Leak Tester',
    date: new Date().toISOString(),
    score: state.summary && state.summary.score,
    niveau: state.summary && state.summary.label,
    identifiantEmpreinte: state.summary && state.summary.fpId,
    unicite: state.summary && state.summary.uniqueness,
    tests: TESTS.map(t => {
      const r = state.results[t.id] || {};
      return {
        id: t.id,
        titre: t.title,
        categorie: CATS[t.cat],
        risque: RISK_LABEL[t.risk],
        statut: STATUS_LABEL[r.status] || '—',
        donnees: Object.fromEntries(r.rows || []),
        remarque: r.note || undefined
      };
    })
  };
}

function exportJSON() {
  const blob = new Blob([JSON.stringify(buildReport(), null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `privacy-report-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function copySummary() {
  const r = buildReport();
  const lines = [
    `Privacy Leak Tester — ${new Date().toLocaleString('fr-FR')}`,
    `Score : ${r.score}/100 (${r.niveau})`,
    `Empreinte : ${r.identifiantEmpreinte} — unicité : ${r.unicite}`,
    '',
    ...r.tests.map(t => `[${t.statut}] ${t.titre}`)
  ];
  const btn = $('#copyBtn');
  try {
    await navigator.clipboard.writeText(lines.join('\n'));
    btn.textContent = '✓ Copié !';
  } catch (e) {
    btn.textContent = '✗ Copie impossible';
  }
  setTimeout(() => { btn.textContent = '⧉ Copier le résumé'; }, 1800);
}

/* ---------- Initialisation ---------- */
$('#runBtn').addEventListener('click', runAll);
$('#exportBtn').addEventListener('click', exportJSON);
$('#copyBtn').addEventListener('click', copySummary);
