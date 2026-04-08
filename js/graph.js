/* =========================================================
   GRAPH.JS — Wrapper MSAL + Microsoft Graph API
   Partagé entre toutes les pages audit.
   Dépend de : msal-browser (chargé avant via CDN)
   ========================================================= */

const GRAPH_CLIENT_ID = "bd7f8225-61af-4ac0-bc6c-aaccd6a22fac";
const GRAPH_SCOPES = [
  "User.Read.All","Directory.Read.All","Policy.Read.All",
  "AuditLog.Read.All","Organization.Read.All","RoleManagement.Read.All",
  "MailboxSettings.Read",
  "UserAuthenticationMethod.Read.All","SecurityEvents.Read.All",
  "DeviceManagementManagedDevices.Read.All","DeviceManagementConfiguration.Read.All",
  "MailboxSettings.Read","Mail.ReadBasic"
];

let _msalInst = null;
let _token    = null;

// ── Instance MSAL (singleton) ──────────────────────────────────────────────────
function _getMsal() {
  if (!_msalInst) {
    _msalInst = new msal.PublicClientApplication({
      auth: {
        clientId:    GRAPH_CLIENT_ID,
        authority:   "https://login.microsoftonline.com/common",
        redirectUri: window.location.origin + "/blank.html"
      },
      cache: { cacheLocation: "sessionStorage", storeAuthStateInCookie: false }
    });
  }
  return _msalInst;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
async function graphLogin() {
  const m = _getMsal();
  const r = await m.loginPopup({ scopes: GRAPH_SCOPES });
  m.setActiveAccount(r.account);
  _token = (await m.acquireTokenSilent({ scopes: GRAPH_SCOPES, account: r.account })).accessToken;

  // Stocker infos tenant pour la sidebar (toutes les pages)
  try {
    const org = await gGet("/organization");
    const t = org?.value?.[0];
    if (t) {
      sessionStorage.setItem("tenant-name", t.displayName || "");
      sessionStorage.setItem("tenant-dom",  t.verifiedDomains?.find(d => d.isDefault)?.name || "");
    }
  } catch {}

  return r.account;
}

async function graphLogout() {
  sessionStorage.clear();
  try { await _getMsal().logoutPopup(); } catch {}
  location.reload();
}

function graphHasSession() {
  return _getMsal().getAllAccounts().length > 0;
}

async function graphGetToken() {
  if (_token) return _token;
  const m   = _getMsal();
  const acc = m.getActiveAccount() || m.getAllAccounts()[0];
  if (!acc) throw new Error("Non authentifié — veuillez vous connecter.");
  m.setActiveAccount(acc);
  _token = (await m.acquireTokenSilent({ scopes: GRAPH_SCOPES, account: acc })).accessToken;
  return _token;
}

async function graphRefreshToken() {
  _token = null;
  return graphGetToken();
}

// ── Requêtes Graph ─────────────────────────────────────────────────────────────
async function gGet(path) {
  const token = await graphGetToken();
  const url   = path.startsWith("http") ? path : "https://graph.microsoft.com/v1.0" + path;
  const r     = await fetch(url, {
    headers: { Authorization: "Bearer " + token, ConsistencyLevel: "eventual" }
  });
  if (r.status === 403) return null; // permission refusée → géré par section
  if (!r.ok) throw new Error("Graph " + r.status + " — " + path.split("?")[0]);
  return r.json();
}

async function gBeta(path) {
  const token = await graphGetToken();
  const r     = await fetch("https://graph.microsoft.com/beta" + path, {
    headers: { Authorization: "Bearer " + token }
  });
  if (!r.ok) return null;
  return r.json();
}

// Pagination automatique — retourne tous les éléments jusqu'à `max`
async function gAll(path, max = 5000) {
  let res = [], next = path;
  while (next && res.length < max) {
    const d = await gGet(next);
    if (!d) break;
    res  = res.concat(d.value || []);
    next = d["@odata.nextLink"] || null;
  }
  return res;
}

async function gGetOrg() {
  const d = await gGet("/organization");
  return d?.value?.[0] || null;
}

// ── Initialisation page ────────────────────────────────────────────────────────
// Appelé au chargement de chaque page connectée.
// onSession(account) : exécuté si session MSAL active
// onNoSession        : exécuté sinon (optionnel)
function graphInitPage(onSession, onNoSession) {
  // Scores dans la sidebar depuis le cache
  ["entra","intune","o365","gpo"].forEach(p => {
    const score = sessionStorage.getItem("score-" + p);
    const el    = document.getElementById("nb-" + p + "-score");
    if (el) el.textContent = score !== null ? score + "/100" : "—";
  });

  // Nav active selon la page courante
  const page = window.location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav-item[data-page]").forEach(el => {
    el.classList.toggle("active", el.dataset.page === page);
  });

  // Infos tenant en cache
  const tName = sessionStorage.getItem("tenant-name");
  const tDom  = sessionStorage.getItem("tenant-dom");
  if (tName) { const el = document.getElementById("nav-tenant-name"); if (el) el.textContent = tName; }
  if (tDom)  { const el = document.getElementById("nav-tenant-dom");  if (el) el.textContent = tDom;  }

  if (graphHasSession()) {
    const m   = _getMsal();
    const acc = m.getAllAccounts()[0];
    if (acc) {
      m.setActiveAccount(acc);
      const el = document.getElementById("nav-user");
      if (el) el.textContent = acc.username;
    }
    const appEl   = document.getElementById("app");
    const loginEl = document.getElementById("login-screen");
    if (appEl)   appEl.style.display   = "block";
    if (loginEl) loginEl.style.display = "none";
    if (onSession) onSession(acc);
  } else {
    if (onNoSession) onNoSession();
  }
}

// ── Helpers UI communs ─────────────────────────────────────────────────────────
function gLoading(txt) {
  const ov = document.getElementById("loading");
  const tx = document.getElementById("loading-text");
  if (ov) ov.classList.add("active");
  if (tx) tx.textContent = txt || "Chargement...";
}
function gLoaded() {
  const ov = document.getElementById("loading");
  if (ov) ov.classList.remove("active");
}
function gShowErr(msg) {
  const el = document.getElementById("error-msg");
  if (!el) return;
  el.style.display = msg ? "block" : "none";
  el.textContent   = msg || "";
}
