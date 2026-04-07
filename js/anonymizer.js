/* =========================================================
   ANONYMIZER.JS — Moteur d'anonymisation GPO
   Usage : resetAnonState() puis anonymize(text, opts)
   ========================================================= */

let _anonMap = {};
let _anonCounters = {};

/**
 * Réinitialise le dictionnaire de correspondances entre deux fichiers.
 * Note : on NE réinitialise PAS entre les fichiers d'un même lot,
 * afin que les mêmes valeurs reçoivent les mêmes tokens.
 */
function resetAnonState() {
  _anonMap = {};
  _anonCounters = {};
}

/**
 * Génère ou récupère un token anonyme pour une valeur donnée.
 * Même valeur → même token (cohérence inter-fichiers).
 * @param {string} type  - Catégorie (SID, GUID, DN, UPN, IP, DOMAIN, USER, PC)
 * @param {string} value - Valeur originale
 * @returns {string}     - Token ex: [SID-1], [DOMAIN-3]
 */
function token(type, value) {
  if (_anonMap[value]) return _anonMap[value];
  _anonCounters[type] = (_anonCounters[type] || 0) + 1;
  const tok = `[${type}-${_anonCounters[type]}]`;
  _anonMap[value] = tok;
  return tok;
}

/**
 * Anonymise un texte selon les options fournies.
 * @param {string} text
 * @param {{ sids, guids, dns, users, ips, domain, computers }} opts
 * @returns {{ out: string, stats: Object }}
 */
function anonymize(text, opts) {
  const countsBefore = Object.assign({}, _anonCounters);
  let out = text;

  // SIDs Windows (S-1-5-21-xxxx-xxxx-xxxx-xxxx et formes courtes)
  if (opts.sids) {
    out = out.replace(/S-1-5-21-\d+-\d+-\d+-\d+/g, m => token('SID', m));
    out = out.replace(/\bS-1-\d(-\d+){2,}/g, m => {
      if (m.length > 8) return token('SID', m);
      return m;
    });
  }

  // Distinguished Names LDAP (CN=...,DC=...)
  if (opts.dns) {
    out = out.replace(
      /(?:CN|OU|DC|O|C)=[^,\s"<>]+(?:,(?:CN|OU|DC|O|C)=[^,\s"<>]+)+/gi,
      m => token('DN', m)
    );
  }

  // GUIDs (avec ou sans accolades)
  if (opts.guids) {
    out = out.replace(
      /\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?/gi,
      m => token('GUID', m)
    );
  }

  // Emails et UPN (user@domain)
  if (opts.users) {
    out = out.replace(
      /[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]{2,}\.[a-zA-Z]{2,}/g,
      m => token('UPN', m)
    );
  }

  // Adresses IP v4
  if (opts.ips) {
    out = out.replace(
      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
      m => token('IP', m)
    );
  }

  // NetBIOS DOMAINE\utilisateur
  if (opts.users || opts.domain) {
    out = out.replace(/([A-Z][A-Z0-9\-]{1,14})\\([A-Za-z0-9\-_.]{1,64})/g, (m, dom, usr) => {
      const d = opts.domain ? token('DOMAIN', dom) : dom;
      const u = opts.users  ? token('USER',   usr) : usr;
      return d + '\\' + u;
    });
  }

  // Noms de machines (heuristique : majuscules + chiffres/tirets)
  if (opts.computers) {
    out = out.replace(/\b([A-Z]{2,}[0-9A-Z\-]{3,})\b/g, m => {
      if (m.startsWith('[')) return m; // déjà un token
      if (/\d/.test(m) || (/-/.test(m) && m.length > 5)) return token('PC', m);
      return m;
    });
  }

  // Noms de domaine DNS (.local, .internal, .corp, etc.)
  if (opts.domain) {
    out = out.replace(
      /\b([a-zA-Z0-9\-]{2,}\.(?:local|internal|corp|lan|ad|domain|fr|com|net|org|eu))\b/gi,
      m => token('DOMAIN', m)
    );
  }

  // Calcul des stats (nombre de remplacements effectués dans cet appel)
  const stats = {};
  for (const [type, count] of Object.entries(_anonCounters)) {
    const delta = count - (countsBefore[type] || 0);
    if (delta > 0) stats[type] = delta;
  }

  return { out, stats };
}

/**
 * Retourne le dictionnaire complet de correspondances (original → token).
 * Utile pour un éventuel rapport de mapping.
 */
function getAnonMap() {
  return Object.assign({}, _anonMap);
}
