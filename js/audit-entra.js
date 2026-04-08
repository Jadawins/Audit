/* =========================================================
   AUDIT-ENTRA.JS — Audit Entra ID / Azure AD
   Dépend de : js/utils.js, js/graph.js
   ========================================================= */

let _entraData = null;
let _uf  = { type: "all", sort: "name", dir: 1 };
let _caf = { type: "all" };

// ── Score /100 ─────────────────────────────────────────────────────────────────
function calcEntraScore(d) {
  const pts = {
    mfa:      d.mfaRate===100 ? 20 : d.mfaRate>=80 ? 12 : d.mfaRate>=50 ? 6 : 0,
    ca:       d.enabledCA.length>=3 ? 20 : d.enabledCA.length>=1 ? 10 : 0,
    legacy:   d.legacyBlocked ? 15 : 0,
    admin:    d.globalAdmins.length<=2 ? 15 : d.globalAdmins.length<=4 ? 7 : 0,
    inactive: d.inactiveUsers.length===0 ? 15 : d.inactiveUsers.length<=3 ? 8 : 0,
    ss:       d.msScore===null ? 0 : d.msScore>=70 ? 15 : d.msScore>=50 ? 8 : 3
  };
  return { pts, total: Object.values(pts).reduce((a, b) => a + b, 0) };
}

// ── Fetch ──────────────────────────────────────────────────────────────────────
async function fetchEntraData(updateFn) {
  const up = updateFn || (() => {});

  up("Informations tenant...");
  const org = await gGetOrg();

  up("Analyse des utilisateurs...");
  const rawUsers = await gAll(
    "/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses,signInActivity,passwordPolicies&$filter=userType eq 'Member'"
  );

  up("Vérification MFA...");
  const authMethods = await gAll("/reports/authenticationMethods/userRegistrationDetails?$top=999");

  up("Politiques d'accès conditionnel...");
  const caRaw     = await gGet("/identity/conditionalAccess/policies");
  const caPolicies = caRaw?.value || [];

  up("Administrateurs globaux...");
  const adminsRaw  = await gGet("/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members");
  const globalAdmins = adminsRaw?.value || [];

  up("Secure Score Microsoft...");
  const ssRaw      = await gGet("/security/secureScores?$top=1");
  const secureScore = ssRaw?.value?.[0];

  // ── Traitement ─────────────────────────────────────────────────────────────
  const d90          = new Date(Date.now() - 90 * 864e5);
  const enabledUsers = rawUsers.filter(u => u.accountEnabled && u.assignedLicenses?.length > 0);
  const memberIds    = new Set(enabledUsers.map(u => u.id));
  const authF        = authMethods.filter(u => memberIds.has(u.id));

  const mfaUsers  = authF.filter(u => u.isMfaRegistered);
  const noMfaUsers = enabledUsers.filter(u => {
    const a = authF.find(x => x.id === u.id);
    return !a || !a.isMfaRegistered;
  });
  const mfaRate = enabledUsers.length
    ? Math.round(mfaUsers.length / enabledUsers.length * 100) : 0;

  // MFA fort = Authenticator push / FIDO2 / Windows Hello / TOTP app
  const strongIds = new Set(authF
    .filter(u => u.isMfaRegistered && u.methodsRegistered?.some(m =>
      ["microsoftAuthenticatorPush","softwareOneTimePasscode","fido2","windowsHelloForBusiness"].includes(m)
    ))
    .map(u => u.id)
  );
  const strongMfaUsers = mfaUsers.filter(u => strongIds.has(u.id));
  const weakMfaUsers   = mfaUsers.filter(u => !strongIds.has(u.id));

  const inactiveUsers = enabledUsers.filter(u =>
    u.signInActivity?.lastSignInDateTime &&
    new Date(u.signInActivity.lastSignInDateTime) < d90
  );
  const neverLogged = enabledUsers.filter(u => !u.signInActivity?.lastSignInDateTime);

  const enabledCA = caPolicies.filter(p => p.state === "enabled");
  const legacyBlocked = caPolicies.some(p =>
    p.state === "enabled" &&
    p.conditions?.clientAppTypes?.some(t => ["exchangeActiveSync","other"].includes(t)) &&
    p.grantControls?.builtInControls?.includes("block")
  );
  const msScore = secureScore
    ? Math.round(secureScore.currentScore / secureScore.maxScore * 100)
    : null;

  return {
    org, enabledUsers, rawUsers,
    noMfaUsers, mfaUsers, strongMfaUsers, weakMfaUsers, mfaRate,
    inactiveUsers, neverLogged,
    globalAdmins, caPolicies, enabledCA, legacyBlocked,
    secureScore, msScore,
    authF
  };
}

// ── Alertes (pour le dashboard) ────────────────────────────────────────────────
function buildEntraAlerts(d) {
  const alerts = [];
  const { noMfaUsers, globalAdmins, legacyBlocked, weakMfaUsers } = d;
  if (noMfaUsers.length > 0)
    alerts.push({ lvl:"red",    msg: noMfaUsers.length+" utilisateur(s) sans MFA" });
  if (globalAdmins.length > 4)
    alerts.push({ lvl:"red",    msg: globalAdmins.length+" admins globaux (recommandé ≤2)" });
  if (!legacyBlocked)
    alerts.push({ lvl:"orange", msg: "Legacy Auth non bloqué" });
  if (weakMfaUsers.length > 0)
    alerts.push({ lvl:"orange", msg: weakMfaUsers.length+" utilisateur(s) avec MFA faible (SMS/appel)" });
  return alerts;
}

// ── Render page complète ───────────────────────────────────────────────────────
function renderEntraPage(d) {
  const { pts, total } = calcEntraScore(d);
  _animateScore(total, "score-circle", "score-num", "score-label", "score-desc");

  // Métriques
  const { enabledUsers, mfaUsers, mfaRate, inactiveUsers, globalAdmins,
          enabledCA, caPolicies, legacyBlocked, msScore, secureScore } = d;

  const mEl = document.getElementById("home-metrics");
  if (mEl) mEl.innerHTML = [
    { lbl:"Utilisateurs licenciés", val:enabledUsers.length, sub:"Membres actifs", cls:"blue" },
    { lbl:"MFA enregistré",  val:mfaRate+"%", sub:mfaUsers.length+"/"+enabledUsers.length, cls:mfaRate===100?"green":mfaRate>=80?"orange":"red" },
    { lbl:"Comptes inactifs",val:inactiveUsers.length, sub:">90 jours", cls:inactiveUsers.length===0?"green":inactiveUsers.length<=5?"orange":"red" },
    { lbl:"Admins globaux",  val:globalAdmins.length, sub:"Recommandé : ≤2", cls:globalAdmins.length<=2?"green":globalAdmins.length<=4?"orange":"red" },
    { lbl:"Politiques CA",   val:enabledCA.length, sub:enabledCA.length+"/"+caPolicies.length+" actives", cls:enabledCA.length>=3?"green":enabledCA.length>=1?"orange":"red" },
    { lbl:"Secure Score MS", val:msScore!==null?msScore+"%":"N/A", sub:msScore!==null?Math.round(secureScore.currentScore)+"/"+Math.round(secureScore.maxScore)+" pts":"Indisponible", cls:msScore===null?"":msScore>=70?"green":msScore>=50?"orange":"red" }
  ].map(_metricCard).join("");

  // Points d'audit
  const cEl = document.getElementById("home-checks");
  if (cEl) cEl.innerHTML = [
    { name:"MFA utilisateurs", desc:mfaUsers.length+"/"+enabledUsers.length+" ("+d.strongMfaUsers.length+" forts)", pts:pts.mfa, max:20, s:mfaRate===100?"green":mfaRate>=80?"orange":"red", val:mfaRate+"%" },
    { name:"Accès conditionnel", desc:enabledCA.length+" active(s) sur "+caPolicies.length, pts:pts.ca, max:20, s:enabledCA.length>=3?"green":enabledCA.length>=1?"orange":"red", val:enabledCA.length+" CA" },
    { name:"Legacy Auth", desc:"Basic Auth / EWS / ActiveSync", pts:pts.legacy, max:15, s:legacyBlocked?"green":"red", val:legacyBlocked?"Bloqué":"Exposé" },
    { name:"Admins globaux", desc:"Recommandé : 2 maximum", pts:pts.admin, max:15, s:globalAdmins.length<=2?"green":globalAdmins.length<=4?"orange":"red", val:globalAdmins.length+" admin(s)" },
    { name:"Comptes inactifs", desc:"Licenciés sans connexion >90j", pts:pts.inactive, max:15, s:inactiveUsers.length===0?"green":inactiveUsers.length<=5?"orange":"red", val:inactiveUsers.length+" compte(s)" },
    { name:"Secure Score MS", desc:msScore!==null?msScore+"% du score max":"Indisponible", pts:pts.ss, max:15, s:msScore===null?"gray":msScore>=70?"green":msScore>=50?"orange":"red", val:msScore!==null?msScore+"%":"N/A" }
  ].map(_checkCard).join("");

  // Recommandations
  _renderEntraRecos(d, pts);

  // Graphique MFA
  _renderMfaChart(d);

  // Tables
  _rebuildUserTable(d);
  _rebuildAdminsTable(d);
  _rebuildCATable(d);

  // Cache score + alertes
  sessionStorage.setItem("score-entra",  total);
  sessionStorage.setItem("alerts-entra", JSON.stringify(buildEntraAlerts(d)));
  // Mettre à jour le badge sidebar si présent sur la même page
  const nb = document.getElementById("nb-entra-score");
  if (nb) nb.textContent = total + "/100";
}

function _renderEntraRecos(d, pts) {
  const el = document.getElementById("home-recos");
  if (!el) return;
  const { noMfaUsers, weakMfaUsers, legacyBlocked, enabledCA, globalAdmins, inactiveUsers } = d;
  const recos = [];
  if (noMfaUsers.length > 0)
    recos.push({ t:"MFA utilisateurs", p:noMfaUsers.length+" utilisateur(s) sans MFA. Forcer via Conditional Access ou Entra Authentication Methods Policy.", l:"red" });
  if (weakMfaUsers.length > 0)
    recos.push({ t:"MFA faible (SMS/Téléphone)", p:weakMfaUsers.length+" utilisateur(s) avec authentification faible. Migrer vers Microsoft Authenticator ou FIDO2.", l:"orange" });
  if (!legacyBlocked)
    recos.push({ t:"Legacy Auth non bloqué", p:"Créer une politique CA ciblant exchangeActiveSync et other avec blocage. Vecteur d'attaque credential stuffing majeur.", l:"red" });
  if (enabledCA.length < 3)
    recos.push({ t:"Accès conditionnel insuffisant", p:enabledCA.length+" politique(s) active(s). Recommandé : blocage legacy auth, exigence MFA, conformité appareils.", l:"orange" });
  if (globalAdmins.length > 2)
    recos.push({ t:"Trop d'administrateurs globaux", p:globalAdmins.length+" admins globaux. Réduire à 2 max, utiliser des rôles délégués (Exchange Admin, User Admin…).", l:"red" });
  if (inactiveUsers.length > 0)
    recos.push({ t:"Comptes inactifs licenciés", p:inactiveUsers.length+" compte(s) sans connexion depuis 90j. Désactiver selon procédures RH.", l:"orange" });

  el.innerHTML = recos.map(r =>
    `<div class="reco${r.l==="red"?" crit":""}"><h4>⚠ ${r.t}</h4><p>${r.p}</p></div>`
  ).join("") +
  `<div class="reco info"><h4>ℹ Migration GDAP recommandée</h4><p>Migrer l'accès MSP vers GDAP via le Partner Center pour un accès granulaire, temporaire et traçable.</p></div>`;
}

// ── Tables ─────────────────────────────────────────────────────────────────────
function _rebuildUserTable(d) {
  _entraData = d;
  const { enabledUsers, noMfaUsers, inactiveUsers, neverLogged } = d;
  const noMfaIds   = new Set(noMfaUsers.map(u => u.id));
  const inactiveIds = new Set(inactiveUsers.map(u => u.id));
  const neverIds    = new Set(neverLogged.map(u => u.id));

  const cntEl = document.getElementById("cnt-all-users");
  if (cntEl) cntEl.textContent = enabledUsers.length + " total";

  // Stocke les sets pour les filtres UI
  _entraData._noMfaIds   = noMfaIds;
  _entraData._inactiveIds = inactiveIds;
  _entraData._neverIds   = neverIds;

  _filterUsersRender();

  document.getElementById("f-users-search")?.addEventListener("input", _filterUsersRender);
}

function _filterUsersRender() {
  if (!_entraData) return;
  const { enabledUsers, _noMfaIds, _inactiveIds, _neverIds } = _entraData;
  if (!_noMfaIds) return;

  const q = (document.getElementById("f-users-search")?.value || "").toLowerCase();
  let users = enabledUsers.filter(u => {
    if (q && !u.displayName?.toLowerCase().includes(q) && !u.userPrincipalName?.toLowerCase().includes(q)) return false;
    if (_uf.type === "nomfa")      return _noMfaIds.has(u.id);
    if (_uf.type === "inactive")   return _inactiveIds.has(u.id);
    if (_uf.type === "neverlogin") return _neverIds.has(u.id);
    return true;
  });

  users = users.sort((a, b) => {
    if (_uf.sort === "login") {
      const da = a.signInActivity?.lastSignInDateTime ? new Date(a.signInActivity.lastSignInDateTime) : new Date(0);
      const db = b.signInActivity?.lastSignInDateTime ? new Date(b.signInActivity.lastSignInDateTime) : new Date(0);
      return (da - db) * _uf.dir;
    }
    return (a.displayName || "").localeCompare(b.displayName || "") * _uf.dir;
  });

  set("f-users-count", users.length + " résultat(s)");
  const tbl = document.getElementById("tbl-all-users");
  if (!tbl) return;
  tbl.innerHTML = users.map(u => {
    const hasMfa   = !_noMfaIds.has(u.id);
    const lastLogin = u.signInActivity?.lastSignInDateTime;
    return `<tr>
      <td>${u.displayName||"—"}</td>
      <td class="mono">${u.userPrincipalName||"—"}</td>
      <td class="mono">${lastLogin ? new Date(lastLogin).toLocaleDateString("fr-FR") : "Jamais"}</td>
      <td><span class="pill pill-${hasMfa?"green":"red"}"><span class="pill-dot"></span>${hasMfa?"MFA OK":"Sans MFA"}</span></td>
      <td>${u.assignedLicenses?.length||0}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="5" class="empty">Aucun résultat</td></tr>';
}

function _rebuildAdminsTable(d) {
  const { globalAdmins, _noMfaIds, _inactiveIds } = d;
  if (!globalAdmins) return;
  set("cnt-admins", globalAdmins.length + " admin(s)");
  const tbl = document.getElementById("tbl-admins");
  if (!tbl) return;
  tbl.innerHTML = globalAdmins.map(u => {
    const noMfaIds   = _noMfaIds   || new Set();
    const inactiveIds = _inactiveIds || new Set();
    const pils = [];
    if (noMfaIds.has(u.id))   pils.push(`<span class="pill pill-red"><span class="pill-dot"></span>Sans MFA</span>`);
    if (inactiveIds.has(u.id)) pils.push(`<span class="pill pill-orange"><span class="pill-dot"></span>Inactif 90j</span>`);
    if (pils.length === 0)     pils.push(`<span class="pill pill-green"><span class="pill-dot"></span>OK</span>`);
    return `<tr>
      <td>${u.displayName||"—"}</td>
      <td class="mono">${u.userPrincipalName||u.mail||"—"}</td>
      <td style="display:flex;gap:.3rem;flex-wrap:wrap">${pils.join("")}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="3" class="empty">Aucun résultat</td></tr>';
}

function _rebuildCATable(d) {
  if (!d) return;
  set("cnt-ca", (d.caPolicies||[]).length + " politique(s)");
  _filterCATable(d.caPolicies || []);
  document.getElementById("f-ca-search")?.addEventListener("input", () => _filterCATable(d.caPolicies || []));
}

function _filterCATable(policies) {
  const q = (document.getElementById("f-ca-search")?.value || "").toLowerCase();
  const filtered = policies.filter(p => {
    if (q && !p.displayName?.toLowerCase().includes(q)) return false;
    if (_caf.type === "enabled")  return p.state === "enabled";
    if (_caf.type === "report")   return p.state === "enabledForReportingButNotEnforced";
    if (_caf.type === "disabled") return p.state === "disabled";
    return true;
  });
  set("f-ca-count", filtered.length + " résultat(s)");
  const tbl = document.getElementById("tbl-ca");
  if (!tbl) return;
  tbl.innerHTML = filtered.map(p => {
    const s  = p.state==="enabled"?"green":p.state==="enabledForReportingButNotEnforced"?"orange":"gray";
    const sl = p.state==="enabled"?"Activée":p.state==="enabledForReportingButNotEnforced"?"Rapport seul":"Désactivée";
    const users = p.conditions?.users?.includeUsers?.includes("All")?"Tous":(p.conditions?.users?.includeGroups?.length||0)+" groupe(s)";
    const ctrl  = p.grantControls?.builtInControls?.join(", ") || "—";
    return `<tr>
      <td>${p.displayName||"—"}</td>
      <td><span class="pill pill-${s}"><span class="pill-dot"></span>${sl}</span></td>
      <td>${users}</td>
      <td class="mono" style="font-size:.68rem">${ctrl}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="4" class="empty">Aucune politique</td></tr>';
}

// ── Graphique ──────────────────────────────────────────────────────────────────
let _mfaChart = null;
function _renderMfaChart(d) {
  const ctx = document.getElementById("chart-mfa");
  if (!ctx) return;
  if (_mfaChart) _mfaChart.destroy();
  _mfaChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["MFA fort","MFA faible","Sans MFA"],
      datasets: [{
        data: [d.strongMfaUsers.length, d.weakMfaUsers.length, d.noMfaUsers.length],
        backgroundColor: ["#22c55e","#f59e0b","#ef4444"],
        borderWidth: 0, hoverOffset: 4
      }]
    },
    options: {
      plugins: { legend: { labels: { color:"#6b7494", font:{ family:"'DM Sans'", size:11 } } } },
      cutout: "70%", maintainAspectRatio: false
    }
  });
}

// ── Filtres UI (appelés via onclick dans le HTML) ──────────────────────────────
function setUserFilter(type, el) {
  _uf.type = type;
  el.closest(".filter-bar").querySelectorAll(".ftag[data-group='utype']").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  _filterUsersRender();
}
function sortUsers(by, el) {
  if (_uf.sort === by) _uf.dir *= -1; else { _uf.sort = by; _uf.dir = 1; }
  document.querySelectorAll("#sort-users-name,#sort-users-login").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  _filterUsersRender();
}
function setCAFilter(type, el) {
  _caf.type = type;
  el.closest(".filter-bar").querySelectorAll(".ftag[data-group='castate']").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  if (_entraData) _filterCATable(_entraData.caPolicies || []);
}

// ── Helpers DOM ────────────────────────────────────────────────────────────────
function _metricCard(m) {
  return `<div class="metric ${m.cls}"><div class="metric-lbl">${m.lbl}</div><div class="metric-val">${m.val}</div><div class="metric-sub">${m.sub||""}</div></div>`;
}
function _checkCard(c) {
  const lbl = c.s==="green"?"OK":c.s==="orange"?"Partiel":c.s==="red"?"Critique":"N/A";
  return `<div class="check-card"><div class="cc-top"><span class="cc-name">${c.name}</span><span class="cc-pts">${c.pts}/${c.max}</span></div><div class="cc-desc">${c.desc}</div><div class="cc-bot"><span class="cc-val">${c.val}</span><span class="pill pill-${c.s}"><span class="pill-dot"></span>${lbl}</span></div></div>`;
}
function _animateScore(score, circleId, numId, labelId, descId) {
  const C = 314;
  const color = score>=80?"#22c55e":score>=60?"#f59e0b":"#ef4444";
  const label = score>=80?"Bon niveau":score>=60?"Niveau moyen":score>=40?"Insuffisant":"Critique";
  const desc  = score>=80?"Posture satisfaisante.":score>=60?"Actions correctives recommandées.":score>=40?"Risques importants identifiés.":"Remédiation urgente nécessaire.";
  const circle = document.getElementById(circleId);
  if (circle) {
    setTimeout(() => { circle.style.strokeDashoffset = C - (score/100)*C; }, 60);
    circle.style.stroke = color;
  }
  const numEl = document.getElementById(numId);
  if (numEl) { numEl.textContent = score; numEl.style.color = color; }
  const lblEl = document.getElementById(labelId);
  if (lblEl) { lblEl.textContent = label; lblEl.style.cssText = `color:${color};background:${color}18`; }
  set(descId, desc);
}

// ── Point d'entrée ─────────────────────────────────────────────────────────────
async function runEntraAudit(updateFn) {
  const data = await fetchEntraData(updateFn);
  _entraData = data;
  renderEntraPage(data);
  return { score: calcEntraScore(data).total, alerts: buildEntraAlerts(data), data };
}
