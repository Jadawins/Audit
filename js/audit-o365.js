/* =========================================================
   AUDIT-O365.JS — Audit Microsoft 365
   Licences gaspillées + règles inbox suspectes
   Dépend de : js/utils.js, js/graph.js
   ========================================================= */

let _o365Data = null;
let _o365f    = { type: "all" };
let _rulesf   = { type: "all" };

// Prix mensuels indicatifs (€ HT) par SKU connu
const LICENSE_PRICES = {
  "O365_BUSINESS_PREMIUM":   22,
  "SPB":                     22,
  "ENTERPRISEPACK":          32, // E3
  "ENTERPRISEPREMIUM":       54, // E5
  "EXCHANGESTANDARD":        4,
  "EXCHANGEENTERPRISE":      8,
  "TEAMS_EXPLORATORY":       0,
  "FLOW_FREE":               0,
  "POWER_BI_STANDARD":       0,
};

// ── Score /100 ─────────────────────────────────────────────────────────────────
function calcO365Score(d) {
  const wastedCount    = d.wastedLicenses.length;
  const suspRulesCount = d.suspiciousRules.length;
  const pts = {
    licenses: wastedCount===0 ? 40 : wastedCount<=5 ? 20 : 0,
    rules:    suspRulesCount===0 ? 60 : suspRulesCount<=2 ? 30 : 0
  };
  return { pts, total: Object.values(pts).reduce((a, b) => a + b, 0) };
}

// ── Fetch ──────────────────────────────────────────────────────────────────────
async function fetchO365Data(updateFn) {
  const up = updateFn || (() => {});

  up("Analyse des licences...");
  const rawUsers = await gAll(
    "/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses,signInActivity,assignedPlans&$filter=userType eq 'Member'"
  );

  up("SKU disponibles...");
  const skuRaw = await gGet("/subscribedSkus");
  const skus   = skuRaw?.value || [];

  // Admins globaux (pour scan prioritaire des règles inbox)
  up("Administrateurs globaux...");
  const adminsRaw    = await gGet("/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members");
  const globalAdmins = adminsRaw?.value || [];

  // MFA pour identifier comptes sans MFA
  up("Données MFA...");
  const authMethods = await gAll("/reports/authenticationMethods/userRegistrationDetails?$top=999");

  // ── Licences gaspillées ─────────────────────────────────────────────────────
  const d90           = new Date(Date.now() - 90 * 864e5);
  const enabledUsers  = rawUsers.filter(u => u.accountEnabled && u.assignedLicenses?.length > 0);
  const disabledUsers = rawUsers.filter(u => !u.accountEnabled && u.assignedLicenses?.length > 0);

  const inactiveWithLicenses = enabledUsers.filter(u =>
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

  // Déduplication par ID
  const wastedMap = new Map();
  wastedLicenses.forEach(u => { if (!wastedMap.has(u.id)) wastedMap.set(u.id, u); });
  const wastedDedup = [...wastedMap.values()];

  // Coût estimé
  const wastedCost = _estimateWastedCost(wastedDedup, skus);

  // ── Règles inbox suspectes ──────────────────────────────────────────────────
  // Cibles prioritaires : admins globaux + comptes sans MFA
  const noMfaIds   = new Set(authMethods.filter(u => !u.isMfaRegistered).map(u => u.id));
  const adminIds   = new Set(globalAdmins.map(u => u.id));
  const priorityIds = new Set([...adminIds, ...noMfaIds]);

  // Scan tous les comptes prioritaires (admins + sans MFA)
  const scanTargets = enabledUsers.filter(u => priorityIds.has(u.id));

  const otherCount = enabledUsers.length - scanTargets.length;

  up("Règles inbox (" + scanTargets.length + " comptes prioritaires)...");
  const rulesResults = await _scanInboxRules(scanTargets, up);

  return {
    enabledUsers, disabledUsers, inactiveWithLicenses, neverLoggedWithLicenses,
    wastedLicenses: wastedDedup, wastedCost, skus,
    globalAdmins, noMfaIds, adminIds,
    scanTargets, otherCount,
    rulesResults,
    suspiciousRules: rulesResults.filter(r => r.suspicious),
    scannedCount: scanTargets.length
  };
}

async function _scanInboxRules(users, updateFn) {
  const results = [];
  for (let i = 0; i < users.length; i++) {
    const u = users[i];
    if (updateFn) updateFn("Règles inbox — " + (i+1) + "/" + users.length + "...");
    // Pause anti-throttling toutes les 10 requêtes
    if (i > 0 && i % 10 === 0) await new Promise(r => setTimeout(r, 200));
    try {
      const data = await gGet("/users/" + u.id + "/mailFolders/inbox/messageRules");
      if (!data) { results.push({ user: u, rules: [], error: "403", suspicious: false }); continue; }
      const rules = data.value || [];
      const flagged = rules.filter(r => _isSuspiciousRule(r));
      if (flagged.length > 0) {
        flagged.forEach(r => results.push({ user: u, rule: r, suspicious: true }));
      }
    } catch(e) {
      results.push({ user: u, rules: [], error: e.message, suspicious: false });
    }
  }
  return results;
}

function _isSuspiciousRule(r) {
  const a = r.actions || {};
  // Suppression silencieuse
  if (a.delete === true) return true;
  // Transfert externe
  if (a.forwardTo?.some(f => f.emailAddress?.address)) return true;
  if (a.forwardAsAttachmentTo?.some(f => f.emailAddress?.address)) return true;
  if (a.redirectTo?.some(f => f.emailAddress?.address)) return true;
  // Marquer comme lu + déplacer (exfiltration discrète)
  if (a.markAsRead && a.moveToFolder) return true;
  return false;
}

function _estimateWastedCost(users, skus) {
  let total = 0;
  const skuMap = {};
  skus.forEach(s => { skuMap[s.skuPartNumber] = s; });

  users.forEach(u => {
    (u.assignedLicenses || []).forEach(lic => {
      const sku = skus.find(s => s.skuId === lic.skuId);
      if (!sku) return;
      const price = LICENSE_PRICES[sku.skuPartNumber] ?? 10; // 10€ par défaut si inconnu
      total += price;
    });
  });
  return total;
}

// ── Alertes (dashboard) ────────────────────────────────────────────────────────
function buildO365Alerts(d) {
  const alerts = [];
  if (d.wastedLicenses.length > 0)
    alerts.push({ lvl:"orange", msg: d.wastedLicenses.length+" licence(s) potentiellement gaspillée(s) (≈"+d.wastedCost+"€/mois)" });
  if (d.suspiciousRules.length > 0)
    alerts.push({ lvl:"red", msg: d.suspiciousRules.length+" règle(s) inbox suspecte(s) détectée(s)" });
  return alerts;
}

// ── Render ─────────────────────────────────────────────────────────────────────
function renderO365Page(d) {
  _o365Data = d;
  const { pts, total } = calcO365Score(d);

  // Score ring
  _animateO365Score(total);

  // Métriques
  const mEl = document.getElementById("o365-metrics");
  if (mEl) mEl.innerHTML = [
    { lbl:"Utilisateurs licenciés", val:d.enabledUsers.length,     sub:"Membres actifs",               cls:"blue" },
    { lbl:"Licences gaspillées",    val:d.wastedLicenses.length,   sub:"Comptes inactifs/désactivés",  cls:d.wastedLicenses.length===0?"green":d.wastedLicenses.length<=5?"orange":"red" },
    { lbl:"Coût estimé gaspillé",   val:"≈"+d.wastedCost+"€",      sub:"Par mois (indicatif)",         cls:d.wastedCost===0?"green":d.wastedCost<100?"orange":"red" },
    { lbl:"Comptes désactivés+lic", val:d.disabledUsers.length,    sub:"Licences inutiles",            cls:d.disabledUsers.length===0?"green":"red" },
    { lbl:"Règles suspectes",       val:d.suspiciousRules.length,  sub:d.scannedCount+" admins/sans-MFA scannés", cls:d.suspiciousRules.length===0?"green":"red" }
  ].map(m => `<div class="metric ${m.cls}"><div class="metric-lbl">${m.lbl}</div><div class="metric-val">${m.val}</div><div class="metric-sub">${m.sub||""}</div></div>`).join("");

  // Points d'audit
  const cEl = document.getElementById("o365-checks");
  if (cEl) cEl.innerHTML = [
    { name:"Licences gaspillées", desc:d.wastedLicenses.length+" compte(s) inactif/désactivé avec licence", pts:pts.licenses, max:40, s:d.wastedLicenses.length===0?"green":d.wastedLicenses.length<=5?"orange":"red", val:d.wastedLicenses.length+" compte(s)" },
    { name:"Règles inbox",        desc:d.suspiciousRules.length+" règle(s) suspecte(s) · scan ciblé sur "+d.scannedCount+" comptes prioritaires (admins globaux + sans MFA)", pts:pts.rules, max:60, s:d.suspiciousRules.length===0?"green":d.suspiciousRules.length<=2?"orange":"red", val:d.suspiciousRules.length+" règle(s)" }
  ].map(c => { const lbl=c.s==="green"?"OK":c.s==="orange"?"Attention":"Critique"; return `<div class="check-card"><div class="cc-top"><span class="cc-name">${c.name}</span><span class="cc-pts">${c.pts}/${c.max}</span></div><div class="cc-desc">${c.desc}</div><div class="cc-bot"><span class="cc-val">${c.val}</span><span class="pill pill-${c.s}"><span class="pill-dot"></span>${lbl}</span></div></div>`; }).join("");

  // Recommandations
  _renderO365Recos(d);

  // Notice scan partiel
  const partialEl = document.getElementById("rules-partial-msg");
  if (partialEl) {
    const totalUsers = d.enabledUsers.length;
    const all403 = d.scannedCount > 0 && d.rulesResults.every(r => r.error === "403");
    partialEl.style.display = "block";
    if (all403) {
      partialEl.style.color = "var(--red)";
      partialEl.textContent = "⚠ Permission refusée (403) sur tous les comptes. Ajoutez MailboxSettings.Read dans les permissions déléguées de l'app Azure AD, puis reconnectez-vous.";
    } else {
      partialEl.style.color = "";
      partialEl.textContent = "Scan ciblé sur " + d.scannedCount + "/" + totalUsers + " comptes prioritaires (administrateurs globaux + utilisateurs sans MFA). "
        + (d.otherCount > 0 ? d.otherCount + " compte(s) non prioritaire(s) non scannés." : "Tous les comptes prioritaires ont été analysés.");
    }
  }

  // Tables
  _renderWastedTable(d);
  _renderRulesTable(d);

  // Cache score
  sessionStorage.setItem("score-o365",  total);
  sessionStorage.setItem("alerts-o365", JSON.stringify(buildO365Alerts(d)));
  const nb = document.getElementById("nb-o365-score"); if (nb) nb.textContent = total + "/100";
}

function _renderO365Recos(d) {
  const el = document.getElementById("o365-recos"); if (!el) return;
  const recos = [];
  if (d.wastedLicenses.length > 0)
    recos.push({ t:"Licences gaspillées (≈"+d.wastedCost+"€/mois)", p:d.wastedLicenses.length+" compte(s) inactifs ou désactivés conservent des licences. Réassigner ou libérer ces licences pour économiser ≈"+d.wastedCost+"€/mois.", l:"orange" });
  if (d.disabledUsers.length > 0)
    recos.push({ t:"Comptes désactivés avec licence", p:d.disabledUsers.length+" compte(s) désactivé(s) ont encore des licences assignées. Les retirer immédiatement.", l:"red" });
  if (d.suspiciousRules.length > 0)
    recos.push({ t:"Règles inbox suspectes", p:d.suspiciousRules.length+" règle(s) configurent une redirection externe, suppression silencieuse ou exfiltration. Investiguer immédiatement.", l:"red" });
  if (d.otherCount > 0)
    recos.push({ t:"Scan incomplet", p:d.otherCount+" compte(s) non prioritaires n'ont pas été scannés. Audit complet disponible avec REEL IT.", l:"info" });
  if (recos.length === 0)
    recos.push({ t:"Aucune anomalie détectée", p:"Aucune licence gaspillée ni règle suspecte détectée sur les comptes prioritaires.", l:"green" });

  el.innerHTML = recos.map(r => `<div class="reco${r.l==="red"?" crit":r.l==="green"?" ok":r.l==="info"?" info":""}"><h4>${r.l==="green"?"✓":"⚠"} ${r.t}</h4><p>${r.p}</p></div>`).join("");
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
    const licCount  = u.assignedLicenses?.length || 0;
    return `<tr>
      <td>${u.displayName||"—"}</td>
      <td class="mono">${u.userPrincipalName||"—"}</td>
      <td class="mono">${lastLogin ? new Date(lastLogin).toLocaleDateString("fr-FR") : "Jamais"}</td>
      <td><span class="pill pill-${u.accountEnabled?"orange":"red"}"><span class="pill-dot"></span>${u.reason}</span></td>
      <td>${licCount} licence(s)</td>
    </tr>`;
  }).join("") || '<tr><td colspan="5" class="empty">Aucune licence gaspillée</td></tr>';
}

function _renderRulesTable(d) {
  set("cnt-rules", d.suspiciousRules.length + " règle(s) suspecte(s)");
  _filterRulesRender();
  document.getElementById("f-rules-search")?.addEventListener("input", _filterRulesRender);

  // Message comptes non scannés
  const msgEl = document.getElementById("rules-partial-msg");
  if (msgEl && d.otherCount > 0) {
    msgEl.style.display = "block";
    msgEl.innerHTML = `<strong>ℹ Scan partiel :</strong> ${d.otherCount} utilisateur(s) non prioritaires non scannés. Audit complet disponible avec <strong>REEL IT</strong>.`;
  }
}

function _filterRulesRender() {
  if (!_o365Data) return;
  const q = (document.getElementById("f-rules-search")?.value || "").toLowerCase();
  let rules = _o365Data.rulesResults.filter(r => r.suspicious).filter(r => {
    if (q && !r.user?.displayName?.toLowerCase().includes(q) && !r.user?.userPrincipalName?.toLowerCase().includes(q)) return false;
    return true;
  });
  set("f-rules-count", rules.length + " résultat(s)");
  const tbl = document.getElementById("tbl-rules"); if (!tbl) return;
  tbl.innerHTML = rules.map(r => {
    const a = r.rule?.actions || {};
    const flags = [];
    if (a.delete)                             flags.push("Suppression");
    if (a.forwardTo?.length)                  flags.push("Transfert: "+a.forwardTo.map(f=>f.emailAddress?.address).join(", "));
    if (a.redirectTo?.length)                 flags.push("Redirection: "+a.redirectTo.map(f=>f.emailAddress?.address).join(", "));
    if (a.markAsRead && a.moveToFolder)        flags.push("Lu+Déplacer");
    return `<tr>
      <td>${r.user?.displayName||"—"}</td>
      <td class="mono">${r.user?.userPrincipalName||"—"}</td>
      <td>${r.rule?.displayName||"(sans nom)"}</td>
      <td style="font-size:.72rem;color:var(--red)">${flags.join(" · ")}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="4" class="empty">Aucune règle suspecte détectée</td></tr>';
}

// ── Filtres UI ─────────────────────────────────────────────────────────────────
function setWastedFilter(type, el) {
  _o365f.type = type;
  el.closest(".filter-bar").querySelectorAll(".ftag[data-group='wtype']").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  _filterWastedRender();
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
