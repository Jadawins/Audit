/* =========================================================
   AUDIT-GPO.JS — Analyse statique XML GPO (offline)
   Aucune connexion Microsoft requise.
   Dépend de : js/utils.js
   ========================================================= */

let _gpoData = null;

// ── Score /100 ─────────────────────────────────────────────────────────────────
function calcGPOScore(findings) {
  const { gpos } = findings;
  if (!gpos || gpos.length === 0) return { pts: {}, total: 0, na: true };

  const total    = gpos.length;
  const unlinked = gpos.filter(g => g.issues.includes("unlinked")).length;
  const empty    = gpos.filter(g => g.issues.includes("empty")).length;

  const unlinkedPct = total ? unlinked / total : 0;
  const emptyPct    = total ? empty    / total : 0;

  const secPresent  = gpos.filter(g => g.hasPasswordPolicy || g.hasLockout || g.hasAudit).length;
  const secPct      = total ? secPresent / total : 0;

  const pts = {
    linked:  unlinkedPct===0 ? 25 : unlinkedPct<=0.15 ? 15 : unlinkedPct<=0.30 ? 7 : 0,
    noEmpty: emptyPct===0    ? 20 : emptyPct<=0.10    ? 12 : 0,
    secSettings: secPct>=0.5 ? 30 : secPct>=0.25 ? 15 : 0,
    structured: findings.cloudCandidates.length > 0 ? 10 : 0,
    hygiene:    (unlinked + empty) === 0 ? 15 : (unlinked + empty) <= 2 ? 7 : 0
  };
  return { pts, total: Object.values(pts).reduce((a, b) => a + b, 0) };
}

// ── Parsing XML ────────────────────────────────────────────────────────────────
function parseGPOXml(xmlText) {
  const parser = new DOMParser();
  const doc    = parser.parseFromString(xmlText, "text/xml");

  if (doc.querySelector("parsererror")) {
    throw new Error("XML invalide — vérifiez le fichier importé.");
  }

  // Format: Get-GPOReport -All -ReportType XML → racine <GPOS> ou <GPO> multiples
  const gpNodes = Array.from(doc.querySelectorAll("GPO"));
  if (gpNodes.length === 0) throw new Error("Aucune GPO trouvée dans le fichier XML.");

  return gpNodes.map(node => _parseGPONode(node));
}

function _parseGPONode(node) {
  const name        = _text(node, "Name");
  const guid        = _text(node, "Identifier > Identifier") || _text(node, "GUID") || "";
  const createdDate = _text(node, "CreatedTime");
  const modifiedDate= _text(node, "ModifiedTime");
  const statusStr   = _text(node, "GpoStatus") || _text(node, "GPOStatus") || "";

  // Liens OU
  const linkNodes = Array.from(node.querySelectorAll("LinksTo"));
  const links     = linkNodes.map(l => _text(l, "SOMPath") || _text(l, "OUPath") || "?");

  // Paramètres de sécurité
  const compSettings   = node.querySelector("Computer");
  const userSettings   = node.querySelector("User");
  const hasAnySettings = _hasContent(compSettings) || _hasContent(userSettings);

  // Politique de mot de passe
  const hasPasswordPolicy = !!node.querySelector("PasswordPolicies, PasswordPolicy, MaximumPasswordAge, MinimumPasswordLength");
  // Verrouillage compte
  const hasLockout = !!node.querySelector("AccountLockoutPolicy, LockoutBadCount, LockoutThreshold");
  // Audit
  const hasAudit = !!node.querySelector("AuditSetting, SecurityOptions");
  // Pare-feu
  const hasFirewall = !!node.querySelector("FirewallSettings, WindowsFirewall");
  // BitLocker
  const hasBitLocker = !!node.querySelector("BitLockerDriveEncryption") ||
    (node.textContent || "").toLowerCase().includes("bitlocker");
  // Paramètres Windows Update
  const hasWUFB = !!node.querySelector("WindowsUpdate") ||
    (node.textContent || "").toLowerCase().includes("windowsupdate");
  // Scripts de connexion
  const hasLoginScript = !!node.querySelector("Scripts");
  // Extensions de sécurité spécifiques
  const hasMSAL = !!(node.textContent || "").toLowerCase().match(/mfa|multifactor|authenticat/);

  // Catégorisation cloud
  const cloudScore = _calcCloudScore({ hasFirewall, hasWUFB, hasBitLocker, hasLoginScript, links });
  const category   = _categorize({ hasAnySettings, cloudScore, links, hasLoginScript });

  // Problèmes
  const issues = [];
  if (links.length === 0)    issues.push("unlinked");
  if (!hasAnySettings)       issues.push("empty");
  if (statusStr.toLowerCase().includes("disabled")) issues.push("disabled");

  return {
    name, guid, createdDate, modifiedDate, statusStr,
    links, hasAnySettings,
    hasPasswordPolicy, hasLockout, hasAudit, hasFirewall, hasBitLocker, hasWUFB, hasLoginScript, hasMSAL,
    cloudScore, category, issues
  };
}

function _text(node, selector) {
  const el = node?.querySelector(selector);
  return el ? (el.textContent || "").trim() : "";
}

function _hasContent(node) {
  if (!node) return false;
  const txt = (node.textContent || "").replace(/\s/g, "");
  return txt.length > 50; // Plus que quelques espaces/balises vides
}

function _calcCloudScore({ hasFirewall, hasWUFB, hasBitLocker, hasLoginScript, links }) {
  let score = 0;
  if (hasWUFB)      score += 3; // gérable via Intune
  if (hasBitLocker) score += 3; // gérable via Intune
  if (!hasLoginScript) score += 1; // pas de script = plus cloud-friendly
  if (links.some(l => l.toLowerCase().includes("computers"))) score += 1;
  return score;
}

function _categorize({ hasAnySettings, cloudScore, links, hasLoginScript }) {
  if (!hasAnySettings) return "inutile";
  if (links.length === 0) return "inutile";
  if (cloudScore >= 5) return "intune";
  if (hasLoginScript) return "ad";       // Scripts de connexion → garder AD
  if (cloudScore >= 2) return "intune";
  return "ad";
}

// ── Analyse globale ────────────────────────────────────────────────────────────
function analyzeGPOs(gpos) {
  const unlinked       = gpos.filter(g => g.issues.includes("unlinked"));
  const empty          = gpos.filter(g => g.issues.includes("empty"));
  const disabled       = gpos.filter(g => g.issues.includes("disabled"));
  const withSecurity   = gpos.filter(g => g.hasPasswordPolicy || g.hasLockout || g.hasAudit);
  const missingMfa     = gpos.filter(g => !g.hasMSAL && !g.hasPasswordPolicy);
  const cloudCandidates = gpos.filter(g => g.category === "intune");
  const keepAD         = gpos.filter(g => g.category === "ad");
  const useless        = gpos.filter(g => g.category === "inutile");

  return {
    gpos, unlinked, empty, disabled, withSecurity,
    missingMfa, cloudCandidates, keepAD, useless
  };
}

// ── Render ─────────────────────────────────────────────────────────────────────
function renderGPOPage(findings) {
  _gpoData = findings;
  const { pts, total, na } = calcGPOScore(findings);

  if (!na) {
    _animateGPOScore(total);
    sessionStorage.setItem("score-gpo", total);
    const nb = document.getElementById("nb-gpo-score"); if (nb) nb.textContent = total + "/100";
  }

  const { gpos, unlinked, empty, cloudCandidates, keepAD, useless } = findings;

  // Métriques
  const mEl = document.getElementById("gpo-metrics");
  if (mEl) mEl.innerHTML = [
    { lbl:"GPO totales",          val:gpos.length,           sub:"Dans le fichier",                    cls:"blue" },
    { lbl:"Sans lien OU",         val:unlinked.length,       sub:"Non appliquées",                     cls:unlinked.length===0?"green":"red" },
    { lbl:"GPO vides",            val:empty.length,          sub:"Aucun paramètre",                    cls:empty.length===0?"green":"orange" },
    { lbl:"Migrer vers Intune",   val:cloudCandidates.length,sub:"Candidats cloud",                    cls:cloudCandidates.length>0?"blue":"green" },
    { lbl:"Conserver (AD)",       val:keepAD.length,         sub:"Scripts / dépendances locales",      cls:"gray" },
    { lbl:"Inutiles / à archiver",val:useless.length,        sub:"Sans OU ni contenu",                cls:useless.length===0?"green":"orange" }
  ].map(m => `<div class="metric ${m.cls}"><div class="metric-lbl">${m.lbl}</div><div class="metric-val">${m.val}</div><div class="metric-sub">${m.sub||""}</div></div>`).join("");

  // Points d'audit
  const cEl = document.getElementById("gpo-checks");
  if (cEl) cEl.innerHTML = [
    { name:"GPO liées à des OUs",       desc:unlinked.length===0?"Toutes les GPO sont liées":unlinked.length+" GPO(s) sans lien", pts:pts.linked,     max:25, s:unlinked.length===0?"green":unlinked.length<=3?"orange":"red", val:gpos.length - unlinked.length+"/"+gpos.length },
    { name:"GPO sans contenu",          desc:empty.length===0?"Aucune GPO vide":empty.length+" GPO(s) vide(s)",                   pts:pts.noEmpty,    max:20, s:empty.length===0?"green":"orange",                             val:empty.length+" vide(s)" },
    { name:"Paramètres de sécurité",    desc:findings.withSecurity.length+" GPO(s) avec politiques de sécurité",                  pts:pts.secSettings,max:30, s:findings.withSecurity.length>0?"green":"red",                  val:findings.withSecurity.length+" GPO(s)" },
    { name:"Candidats cloud identifiés",desc:cloudCandidates.length+" GPO(s) migrables vers Intune",                              pts:pts.structured, max:10, s:cloudCandidates.length>0?"blue":"gray",                       val:cloudCandidates.length+" GPO(s)" },
    { name:"Hygiène globale",           desc:(unlinked.length+empty.length)===0?"Aucun problème de base":((unlinked.length+empty.length)+" problème(s) identifié(s)"), pts:pts.hygiene, max:15, s:(unlinked.length+empty.length)===0?"green":(unlinked.length+empty.length)<=2?"orange":"red", val:(unlinked.length+empty.length)+" problème(s)" }
  ].map(c => { const lbl=c.s==="green"?"OK":c.s==="orange"?"Attention":c.s==="red"?"Critique":c.s==="blue"?"Info":"N/A"; return `<div class="check-card"><div class="cc-top"><span class="cc-name">${c.name}</span><span class="cc-pts">${c.pts}/${c.max}</span></div><div class="cc-desc">${c.desc}</div><div class="cc-bot"><span class="cc-val">${c.val}</span><span class="pill pill-${c.s}"><span class="pill-dot"></span>${lbl}</span></div></div>`; }).join("");

  // Recommandations
  _renderGPORecos(findings);

  // Table GPO principale
  _renderGPOTable(findings);
}

function _renderGPORecos(f) {
  const el = document.getElementById("gpo-recos"); if (!el) return;
  const recos = [];
  if (f.unlinked.length > 0)
    recos.push({ t:f.unlinked.length+" GPO(s) sans lien OU", p:"Ces GPO ne sont appliquées nulle part. Supprimer ou lier selon l'usage : "+f.unlinked.slice(0,3).map(g=>g.name).join(", ")+(f.unlinked.length>3?"…":""), l:"red" });
  if (f.empty.length > 0)
    recos.push({ t:f.empty.length+" GPO(s) vide(s)", p:"Ces GPO ne contiennent aucun paramètre. Archiver ou supprimer : "+f.empty.slice(0,3).map(g=>g.name).join(", "), l:"orange" });
  if (f.cloudCandidates.length > 0)
    recos.push({ t:f.cloudCandidates.length+" GPO(s) migrables vers Intune", p:"Ces GPO gèrent BitLocker, Windows Update ou des paramètres de conformité — fonctionnalités disponibles nativement dans Intune sans infrastructure AD.", l:"info" });
  if (f.missingMfa.length > 0)
    recos.push({ t:"Paramètres MFA/sécurité absents", p:"Aucune GPO ne configure de politique d'authentification forte. Considérer une GPO de restriction NTLM et la redirection vers Entra ID pour MFA.", l:"orange" });
  if (recos.length === 0)
    recos.push({ t:"GPO bien structurées", p:"Toutes les GPO sont liées, non vides et catégorisées correctement.", l:"green" });

  el.innerHTML = recos.map(r => `<div class="reco${r.l==="red"?" crit":r.l==="green"?" ok":r.l==="info"?" info":""}"><h4>${r.l==="green"?"✓":"⚠"} ${r.t}</h4><p>${r.p}</p></div>`).join("");
}

function _renderGPOTable(findings) {
  set("cnt-gpo", findings.gpos.length + " GPO(s)");
  _filterGPOTable();
  document.getElementById("f-gpo-search")?.addEventListener("input", _filterGPOTable);
}

let _gpof = { type: "all" };
function _filterGPOTable() {
  if (!_gpoData) return;
  const q = (document.getElementById("f-gpo-search")?.value || "").toLowerCase();
  let gpos = _gpoData.gpos.filter(g => {
    if (q && !g.name.toLowerCase().includes(q)) return false;
    if (_gpof.type === "unlinked")  return g.issues.includes("unlinked");
    if (_gpof.type === "empty")     return g.issues.includes("empty");
    if (_gpof.type === "intune")    return g.category === "intune";
    if (_gpof.type === "ad")        return g.category === "ad";
    if (_gpof.type === "useless")   return g.category === "inutile";
    return true;
  });
  set("f-gpo-count", gpos.length + " résultat(s)");
  const tbl = document.getElementById("tbl-gpo"); if (!tbl) return;
  tbl.innerHTML = gpos.map(g => {
    const issuePills = g.issues.map(i => {
      const lbl = i==="unlinked"?"Sans lien":i==="empty"?"Vide":i==="disabled"?"Désactivée":"?";
      return `<span class="pill pill-${i==="unlinked"?"red":"orange'}"><span class="pill-dot"></span>${lbl}</span>`;
    }).join("");
    const catColor  = g.category==="intune"?"blue":g.category==="inutile"?"gray":"green";
    const catLabel  = g.category==="intune"?"→ Intune":g.category==="inutile"?"Inutile":"Conserver AD";
    const secIcons  = [
      g.hasPasswordPolicy ? "🔑" : "",
      g.hasLockout        ? "🔒" : "",
      g.hasAudit          ? "📋" : "",
      g.hasFirewall       ? "🛡" : "",
      g.hasBitLocker      ? "💾" : "",
    ].filter(Boolean).join(" ") || "—";
    return `<tr>
      <td>${g.name}</td>
      <td>${g.links.length ? g.links.slice(0,2).join(", ")+(g.links.length>2?"…":"") : "—"}</td>
      <td>${secIcons}</td>
      <td style="display:flex;gap:.3rem;flex-wrap:wrap">${issuePills||"<span style='color:var(--green)'>OK</span>"}</td>
      <td><span class="pill pill-${catColor}"><span class="pill-dot"></span>${catLabel}</span></td>
    </tr>`;
  }).join("") || '<tr><td colspan="5" class="empty">Aucune GPO</td></tr>';
}

function setGPOFilter(type, el) {
  _gpof.type = type;
  el.closest(".filter-bar").querySelectorAll(".ftag[data-group='gtype']").forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  _filterGPOTable();
}

// ── Score ring ─────────────────────────────────────────────────────────────────
function _animateGPOScore(score) {
  const C = 314;
  const color = score>=80?"#22c55e":score>=60?"#f59e0b":"#ef4444";
  const label = score>=80?"Bien structuré":score>=60?"À optimiser":score>=40?"Problèmes identifiés":"Révision nécessaire";
  const circle = document.getElementById("score-circle");
  if (circle) { setTimeout(() => { circle.style.strokeDashoffset = C - (score/100)*C; }, 60); circle.style.stroke = color; }
  const numEl = document.getElementById("score-num"); if (numEl) { numEl.textContent = score; numEl.style.color = color; }
  const lblEl = document.getElementById("score-label"); if (lblEl) { lblEl.textContent = label; lblEl.style.cssText = `color:${color};background:${color}18`; }
  set("score-desc", "Basé sur "+(_gpoData?.gpos?.length||0)+" GPO(s) analysées.");
}

// ── Point d'entrée ─────────────────────────────────────────────────────────────
function runGPOAudit(xmlText) {
  const gpos     = parseGPOXml(xmlText);
  const findings = analyzeGPOs(gpos);
  _gpoData = findings;
  renderGPOPage(findings);
  return { score: calcGPOScore(findings).total, findings };
}
