/* =========================================================
   AUDIT-O365.JS — Audit Microsoft 365
   Licences gaspillées + Forwarding externe + Apps OAuth
   Dépend de : js/utils.js, js/graph.js
   ========================================================= */

let _o365Data = null;
let _o365f    = { type: "all" };
let _oauthf   = { type: "all" };

// Prix mensuels indicatifs (€ HT) par SKU connu
const LICENSE_PRICES = {
  "O365_BUSINESS_PREMIUM":   22,
  "SPB":                     22,
  "ENTERPRISEPACK":          32,
  "ENTERPRISEPREMIUM":       54,
  "EXCHANGESTANDARD":        4,
  "EXCHANGEENTERPRISE":      8,
  "TEAMS_EXPLORATORY":       0,
  "FLOW_FREE":               0,
  "POWER_BI_STANDARD":       0,
};

const SENSITIVE_SCOPES = new Set([
  "Mail.Read","Mail.ReadWrite","Mail.ReadBasic",
  "Files.Read.All","Files.ReadWrite","Files.ReadWrite.All",
  "Calendars.Read","Calendars.ReadWrite",
  "Contacts.Read","Contacts.ReadWrite",
  "User.Read.All","Directory.Read.All","Directory.ReadWrite.All",
  "offline_access"
]);

// ── Score /100 ─────────────────────────────────────────────────────────────────
function calcO365Score(d) {
  const pts = {
    licenses: d.wastedLicenses.length===0 ? 30 : d.wastedLicenses.length<=5 ? 15 : 0,
    oauth:    d.riskyOAuthApps.length===0  ? 30 : d.riskyOAuthApps.length<=3 ? 15 : 0,
    admins:   d.adminsWithMailbox.length===0 ? 20 : d.adminsWithMailbox.length<=2 ? 10 : 0,
    inbox:    d.inboxRules.length===0 ? 20 : d.inboxRules.length<=2 ? 10 : 0
  };
  return { pts, total: Object.values(pts).reduce((a, b) => a + b, 0) };
}

// ── Fetch ──────────────────────────────────────────────────────────────────────
async function fetchO365Data(updateFn) {
  const up = updateFn || (() => {});

  up("Analyse des licences...");
  const rawUsers = await gAll(
    "/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses,signInActivity&$filter=userType eq 'Member'"
  );

  up("SKU disponibles...");
  const skuRaw = await gGet("/subscribedSkus");
  const skus   = skuRaw?.value || [];

  up("Informations tenant...");
  const orgRaw = await gGet("/organization");
  const tenantDomains = new Set(
    (orgRaw?.value?.[0]?.verifiedDomains || []).map(d => d.name.toLowerCase())
  );

  // ── Licences gaspillées ─────────────────────────────────────────────────────
  const d90           = new Date(Date.now() - 90 * 864e5);
  const enabledUsers  = rawUsers.filter(u => u.accountEnabled && u.assignedLicenses?.length > 0);
  const disabledUsers = rawUsers.filter(u => !u.accountEnabled && u.assignedLicenses?.length > 0);

  const inactiveWithLicenses    = enabledUsers.filter(u =>
    u.signInActivity?.lastSignInDateTime &&
    new Date(u.signInActivity.lastSignInDateTime) < d90
  );
  const neverLoggedWithLicenses = enabledUsers.filter(u =>
    !u.signInActivity?.lastSignInDateTime && u.assignedLicenses?.length > 0
  );

  const wastedLicenses = [
    ...inactiveWithLicenses.map(u => ({ ...u, reason: "Inactif >90j" })),
    ...disabledUsers.map(u => ({ ...u, reason: "Compte désactivé" })),
    ...neverLoggedWithLicenses.map(u => ({ ...u, reason: "Jamais connecté" }))
  ];
  const wastedMap = new Map();
  wastedLicenses.forEach(u => { if (!wastedMap.has(u.id)) wastedMap.set(u.id, u); });
  const wastedDedup = [...wastedMap.values()];
  const wastedCost  = _estimateWastedCost(wastedDedup, skus);

  // ── Apps OAuth tierces sensibles ────────────────────────────────────────────
  const riskyOAuthApps = await _checkOAuthApps(up);

  // ── Admins globaux ───────────────────────────────────────────────────────────
  up("Administrateurs globaux...");
  const adminsRaw    = await gGet("/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members");
  const globalAdmins = adminsRaw?.value || [];
  const adminsWithMailbox = globalAdmins.filter(a =>
    rawUsers.find(u => u.id === a.id && u.assignedLicenses?.length > 0)
  );

  // ── Règles inbox via VPS (client_credentials) ────────────────────────────────
  up("Règles inbox (via serveur)...");
  const tenantId     = sessionStorage.getItem("tenant-id");
  const noMfaIds     = new Set();
  const adminIds     = new Set(globalAdmins.map(u => u.id));
  const scanTargets  = enabledUsers.filter(u => adminIds.has(u.id)).map(u => ({ id: u.id, displayName: u.displayName, userPrincipalName: u.userPrincipalName }));
  const inboxRules   = tenantId ? await _scanInboxRulesViaServer(tenantId, scanTargets, up) : [];

  return {
    enabledUsers, disabledUsers, inactiveWithLicenses, neverLoggedWithLicenses,
    wastedLicenses: wastedDedup, wastedCost, skus,
    globalAdmins, adminsWithMailbox,
    riskyOAuthApps, tenantDomains,
    inboxRules, scanTargets
  };
}

async function _scanInboxRulesViaServer(tenantId, users, updateFn) {
  try {
    const res = await fetch("https://auditms.fr/api/inbox-rules", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ tenantId, users })
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.results || [];
  } catch { return []; }
}


// ── Apps OAuth tierces sensibles ────────────────────────────────────────────────
async function _checkOAuthApps(updateFn) {
  if (updateFn) updateFn("Applications OAuth tierces...");

  const grants = await gAll("/oauth2PermissionGrants?$top=999");
  if (!grants?.length) return [];

  // Filtrer grants avec scopes sensibles
  const flaggedGrants = grants.filter(g =>
    (g.scope || "").split(" ").some(s => SENSITIVE_SCOPES.has(s))
  );

  // Lookup noms des service principals — en parallèle (max 40)
  const clientIds = [...new Set(flaggedGrants.map(g => g.clientId))].slice(0, 40);
  const spResults = await Promise.all(
    clientIds.map(id => gGet("/servicePrincipals/" + id + "?$select=id,displayName,publisherName,verifiedPublisher").catch(() => null))
  );
  const spMap = {};
  spResults.forEach(sp => { if (sp?.id) spMap[sp.id] = sp; });

  // Dédupliquer par app (consentType AllPrincipals > Principal)
  const appMap = new Map();
  flaggedGrants.forEach(g => {
    const scopes = (g.scope || "").split(" ").filter(s => SENSITIVE_SCOPES.has(s));
    if (!scopes.length) return;
    const existing = appMap.get(g.clientId);
    const isAdmin  = g.consentType === "AllPrincipals";
    if (!existing || (isAdmin && existing.consentType !== "AllPrincipals")) {
      const sp = spMap[g.clientId] || {};
      const highRisk = scopes.some(s => ["Mail.ReadWrite","Files.ReadWrite.All","Directory.ReadWrite.All"].includes(s));
      appMap.set(g.clientId, {
        appName:     sp.displayName || g.clientId,
        publisher:   sp.verifiedPublisher?.displayName || sp.publisherName || "Inconnu",
        consentType: g.consentType,
        scopes,
        risk:        highRisk ? "red" : "orange"
      });
    }
  });

  return [...appMap.values()].sort((a, b) => a.risk === "red" ? -1 : 1);
}

function _estimateWastedCost(users, skus) {
  let total = 0;
  users.forEach(u => {
    (u.assignedLicenses || []).forEach(lic => {
      const sku   = skus.find(s => s.skuId === lic.skuId);
      const price = sku ? (LICENSE_PRICES[sku.skuPartNumber] ?? 10) : 10;
      total += price;
    });
  });
  return total;
}

// ── Alertes (dashboard) ────────────────────────────────────────────────────────
function buildO365Alerts(d) {
  const alerts = [];
  if (d.inboxRules.length > 0)
    alerts.push({ lvl:"red", msg: d.inboxRules.length+" règle(s) inbox suspecte(s) sur les admins globaux" });
  if (d.wastedLicenses.length > 0)
    alerts.push({ lvl:"orange", msg: d.wastedLicenses.length+" licence(s) potentiellement gaspillée(s) (≈"+d.wastedCost+"€/mois)" });
  if (d.riskyOAuthApps.filter(a => a.risk==="red").length > 0)
    alerts.push({ lvl:"red", msg: d.riskyOAuthApps.filter(a=>a.risk==="red").length+" app(s) OAuth à haut risque (Mail.ReadWrite / Files.ReadWrite.All)" });
  else if (d.riskyOAuthApps.length > 0)
    alerts.push({ lvl:"orange", msg: d.riskyOAuthApps.length+" app(s) tierce(s) avec accès sensibles (OAuth)" });
  if (d.adminsWithMailbox.length > 0)
    alerts.push({ lvl:"orange", msg: d.adminsWithMailbox.length+" admin(s) global(aux) sans compte dédié" });
  return alerts;
}

// ── Render ─────────────────────────────────────────────────────────────────────
function renderO365Page(d) {
  _o365Data = d;
  const { pts, total } = calcO365Score(d);

  _animateO365Score(total);

  // Métriques
  const mEl = document.getElementById("o365-metrics");
  if (mEl) mEl.innerHTML = [
    { lbl:"Utilisateurs licenciés",  val:d.enabledUsers.length,        sub:"Membres actifs",                cls:"blue" },
    { lbl:"Licences gaspillées",     val:d.wastedLicenses.length,      sub:"Inactifs/désactivés",           cls:d.wastedLicenses.length===0?"green":d.wastedLicenses.length<=5?"orange":"red" },
    { lbl:"Coût estimé gaspillé",    val:"≈"+d.wastedCost+"€",         sub:"Par mois (indicatif)",          cls:d.wastedCost===0?"green":d.wastedCost<100?"orange":"red" },
    { lbl:"Apps OAuth sensibles",    val:d.riskyOAuthApps.length,      sub:"Accès mail/fichiers tiers",     cls:d.riskyOAuthApps.length===0?"green":d.riskyOAuthApps.length<=3?"orange":"red" },
    { lbl:"Règles inbox suspectes",  val:d.inboxRules.length,          sub:d.scanTargets.length+" admins scannés", cls:d.inboxRules.length===0?"green":"red" },
    { lbl:"Admins sans compte dédié",val:d.adminsWithMailbox.length,   sub:"Admins avec boîte mail active", cls:d.adminsWithMailbox.length===0?"green":d.adminsWithMailbox.length<=2?"orange":"red" }
  ].map(m => `<div class="metric ${m.cls}"><div class="metric-lbl">${m.lbl}</div><div class="metric-val">${m.val}</div><div class="metric-sub">${m.sub||""}</div></div>`).join("");

  // Points d'audit
  const cEl = document.getElementById("o365-checks");
  if (cEl) cEl.innerHTML = [
    { name:"Licences gaspillées",     desc:d.wastedLicenses.length+" compte(s) inactif/désactivé avec licence",          pts:pts.licenses, max:30, s:d.wastedLicenses.length===0?"green":d.wastedLicenses.length<=5?"orange":"red",     val:d.wastedLicenses.length+" compte(s)" },
    { name:"Apps OAuth tierces",      desc:d.riskyOAuthApps.length+" app(s) tierce(s) avec scopes sensibles consentis",  pts:pts.oauth,    max:30, s:d.riskyOAuthApps.length===0?"green":d.riskyOAuthApps.length<=3?"orange":"red",     val:d.riskyOAuthApps.length+" app(s)" },
    { name:"Règles inbox suspectes",  desc:d.inboxRules.length+" règle(s) suspecte(s) sur "+d.scanTargets.length+" admins scannés", pts:pts.inbox, max:20, s:d.inboxRules.length===0?"green":"red", val:d.inboxRules.length+" règle(s)" },
    { name:"Admins sans compte dédié",desc:d.adminsWithMailbox.length+" admin(s) global(aux) avec boîte mail active",    pts:pts.admins,   max:20, s:d.adminsWithMailbox.length===0?"green":d.adminsWithMailbox.length<=2?"orange":"red", val:d.adminsWithMailbox.length+" admin(s)" }
  ].map(c => { const lbl=c.s==="green"?"OK":c.s==="orange"?"Attention":"Critique"; return `<div class="check-card"><div class="cc-top"><span class="cc-name">${c.name}</span><span class="cc-pts">${c.pts}/${c.max}</span></div><div class="cc-desc">${c.desc}</div><div class="cc-bot"><span class="cc-val">${c.val}</span><span class="pill pill-${c.s}"><span class="pill-dot"></span>${lbl}</span></div></div>`; }).join("");

  _renderO365Recos(d);
  _renderWastedTable(d);
  _renderInboxRulesTable(d);
  _renderOAuthTable(d);
  _renderAdminsTable(d);

  sessionStorage.setItem("score-o365",  total);
  sessionStorage.setItem("alerts-o365", JSON.stringify(buildO365Alerts(d)));
  const nb = document.getElementById("nb-o365-score"); if (nb) nb.textContent = total + "/100";
}

function _renderO365Recos(d) {
  const el = document.getElementById("o365-recos"); if (!el) return;
  const recos = [];
  if (d.riskyOAuthApps.filter(a => a.risk==="red").length > 0)
    recos.push({ t:"Applications OAuth à haut risque", p:d.riskyOAuthApps.filter(a=>a.risk==="red").length+" app(s) ont accès Mail.ReadWrite ou Files.ReadWrite.All. Révoquer les apps non reconnues via Azure AD → Enterprise applications.", l:"red" });
  if (d.riskyOAuthApps.filter(a => a.risk==="orange").length > 0)
    recos.push({ t:"Applications OAuth avec accès sensibles", p:d.riskyOAuthApps.filter(a=>a.risk==="orange").length+" app(s) ont accès aux mails ou calendriers. Vérifier leur légitimité.", l:"orange" });
  if (d.adminsWithMailbox.length > 0)
    recos.push({ t:"Admins globaux sans compte dédié", p:d.adminsWithMailbox.length+" admin(s) global(aux) utilisent un compte avec boîte mail. Bonne pratique : compte admin dédié sans licence Exchange pour limiter la surface d'attaque.", l:"orange" });
  if (d.disabledUsers.length > 0)
    recos.push({ t:"Comptes désactivés avec licence", p:d.disabledUsers.length+" compte(s) désactivé(s) ont encore des licences. À retirer immédiatement.", l:"red" });
  if (d.wastedLicenses.length > 0)
    recos.push({ t:"Licences gaspillées (≈"+d.wastedCost+"€/mois)", p:d.wastedLicenses.length+" compte(s) inactifs ou désactivés conservent des licences.", l:"orange" });
  if (recos.length === 0)
    recos.push({ t:"Aucune anomalie détectée", p:"Aucune app OAuth suspecte, aucun admin sans compte dédié, aucune licence gaspillée.", l:"green" });
  el.innerHTML = recos.map(r => `<div class="reco${r.l==="red"?" crit":r.l==="green"?" ok":""}"><h4>${r.l==="green"?"✓":"⚠"} ${r.t}</h4><p>${r.p}</p></div>`).join("");
}

function _renderWastedTable(d) {
  set("cnt-wasted", d.wastedLicenses.length + " compte(s)");
  _filterWastedRender();
  document.getElementById("f-wasted-search")?.addEventListener("input", _filterWastedRender);
}

function _filterWastedRender() {
  if (!_o365Data) return;
  const q = (document.getElementById("f-wasted-search")?.value || "").toLowerCase();
  let users = _o365Data.wastedLicenses.filter(u => {
    if (q && !u.displayName?.toLowerCase().includes(q) && !u.userPrincipalName?.toLowerCase().includes(q)) return false;
    if (_o365f.type === "disabled") return !u.accountEnabled;
    if (_o365f.type === "inactive") return u.accountEnabled && u.reason === "Inactif >90j";
    if (_o365f.type === "never")    return u.accountEnabled && u.reason === "Jamais connecté";
    return true;
  });
  set("f-wasted-count", users.length + " résultat(s)");
  const tbl = document.getElementById("tbl-wasted"); if (!tbl) return;
  tbl.innerHTML = users.map(u => {
    const lastLogin = u.signInActivity?.lastSignInDateTime;
    return `<tr>
      <td>${u.displayName||"—"}</td>
      <td class="mono">${u.userPrincipalName||"—"}</td>
      <td class="mono">${lastLogin ? new Date(lastLogin).toLocaleDateString("fr-FR") : "Jamais"}</td>
      <td><span class="pill pill-${u.accountEnabled?"orange":"red"}"><span class="pill-dot"></span>${u.reason}</span></td>
      <td>${u.assignedLicenses?.length||0} licence(s)</td>
    </tr>`;
  }).join("") || '<tr><td colspan="5" class="empty">Aucune licence gaspillée</td></tr>';
}

function _renderInboxRulesTable(d) {
  set("cnt-inbox-rules", d.inboxRules.length + " règle(s) suspecte(s)");
  const tbl = document.getElementById("tbl-inbox-rules"); if (!tbl) return;
  tbl.innerHTML = d.inboxRules.map(r => `<tr>
    <td>${r.displayName||"—"}</td>
    <td class="mono">${r.upn||"—"}</td>
    <td>${r.ruleName||"(sans nom)"}</td>
    <td style="font-size:.72rem;color:var(--red)">${r.flags.join(" · ")}</td>
  </tr>`).join("") || '<tr><td colspan="4" class="empty">Aucune règle suspecte détectée sur les admins</td></tr>';
}

function _renderAdminsTable(d) {
  set("cnt-admins-o365", d.adminsWithMailbox.length + " admin(s)");
  const tbl = document.getElementById("tbl-admins-o365"); if (!tbl) return;
  tbl.innerHTML = d.adminsWithMailbox.map(a => `<tr>
    <td>${a.displayName||"—"}</td>
    <td class="mono">${a.userPrincipalName||"—"}</td>
    <td><span class="pill pill-orange"><span class="pill-dot"></span>Compte avec boîte mail</span></td>
  </tr>`).join("") || '<tr><td colspan="3" class="empty">Tous les admins ont un compte dédié</td></tr>';
}

function _renderOAuthTable(d) {
  set("cnt-oauth", d.riskyOAuthApps.length + " app(s)");
  _filterOAuthRender();
  document.getElementById("f-oauth-search")?.addEventListener("input", _filterOAuthRender);
}

function _filterOAuthRender() {
  if (!_o365Data) return;
  const q = (document.getElementById("f-oauth-search")?.value || "").toLowerCase();
  let apps = _o365Data.riskyOAuthApps.filter(a => {
    if (q && !a.appName?.toLowerCase().includes(q) && !a.publisher?.toLowerCase().includes(q)) return false;
    if (_oauthf.type === "red")    return a.risk === "red";
    if (_oauthf.type === "orange") return a.risk === "orange";
    if (_oauthf.type === "admin")  return a.consentType === "AllPrincipals";
    return true;
  });
  set("f-oauth-count", apps.length + " résultat(s)");
  const tbl = document.getElementById("tbl-oauth"); if (!tbl) return;
  tbl.innerHTML = apps.map(a => `<tr>
    <td>${a.appName}</td>
    <td style="font-size:.7rem;color:var(--text2)">${a.publisher}</td>
    <td><span class="pill pill-${a.consentType==="AllPrincipals"?"red":"orange"}"><span class="pill-dot"></span>${a.consentType==="AllPrincipals"?"Tous les utilisateurs":"Utilisateur(s)"}</span></td>
    <td style="font-size:.7rem">${a.scopes.join(", ")}</td>
    <td><span class="pill pill-${a.risk}"><span class="pill-dot"></span>${a.risk==="red"?"Critique":"Attention"}</span></td>
  </tr>`).join("") || '<tr><td colspan="5" class="empty">Aucune app OAuth suspecte détectée</td></tr>';
}

// ── Filtres UI ─────────────────────────────────────────────────────────────────
function setWastedFilter(type, el) {
  _o365f.type = type;
  el.closest(".filter-bar").querySelectorAll(".ftag[data-group='wtype']").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  _filterWastedRender();
}

function setOAuthFilter(type, el) {
  _oauthf.type = type;
  el.closest(".filter-bar").querySelectorAll(".ftag[data-group='otype']").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  _filterOAuthRender();
}

// ── Score ring ─────────────────────────────────────────────────────────────────
function _animateO365Score(score) {
  const C = 314;
  const color = score>=80?"#22c55e":score>=60?"#f59e0b":"#ef4444";
  const label = score>=80?"Bon niveau":score>=60?"Niveau moyen":score>=40?"Insuffisant":"Critique";
  const circle = document.getElementById("score-circle");
  if (circle) { setTimeout(() => { circle.style.strokeDashoffset = C - (score/100)*C; }, 60); circle.style.stroke = color; }
  const numEl = document.getElementById("score-num"); if (numEl) { numEl.textContent = score; numEl.style.color = color; }
  const lblEl = document.getElementById("score-label"); if (lblEl) { lblEl.textContent = label; lblEl.style.cssText = `color:${color};background:${color}18`; }
  set("score-desc", score>=80?"Aucune anomalie critique.":score>=60?"Quelques points d'attention.":"Anomalies détectées.");
}

// ── Point d'entrée ─────────────────────────────────────────────────────────────
async function runO365Audit(updateFn) {
  const data = await fetchO365Data(updateFn);
  _o365Data = data;
  renderO365Page(data);
  return { score: calcO365Score(data).total, alerts: buildO365Alerts(data), data };
}
