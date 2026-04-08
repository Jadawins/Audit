/* =========================================================
   AUDIT-INTUNE.JS — Audit Intune / Conformité appareils
   Dépend de : js/utils.js, js/graph.js
   ========================================================= */

let _intuneData = null;
let _df = { compliance: "all", os: "all" };

// ── Score /100 ─────────────────────────────────────────────────────────────────
function calcIntuneScore(d) {
  if (!d.available) return { pts: {}, total: 0, na: true };

  const { devices, complianceRate, encryptedRate, pinRate, upToDateRate } = d;

  const pts = {
    compliance:  complianceRate===100 ? 30 : complianceRate>=80 ? 20 : complianceRate>=50 ? 10 : 0,
    encryption:  encryptedRate>=90    ? 25 : encryptedRate>=70  ? 15 : 0,
    pin:         pinRate>=90          ? 25 : pinRate>=70        ? 15 : 0,
    osUpToDate:  upToDateRate>=80     ? 20 : upToDateRate>=50   ? 10 : 0
  };
  return { pts, total: Object.values(pts).reduce((a, b) => a + b, 0) };
}

// ── Fetch ──────────────────────────────────────────────────────────────────────
async function fetchIntuneData(updateFn) {
  const up = updateFn || (() => {});

  up("Appareils Intune...");
  const devRaw = await gGet(
    "/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState," +
    "userDisplayName,userPrincipalName,lastSyncDateTime,isEncrypted,isSupervised,managedDeviceOwnerType," +
    "enrolledDateTime,deviceEnrollmentType,deviceRegistrationState&$top=999"
  );

  // Si pas de licence Intune ou pas de permission → null
  if (!devRaw) {
    return { available: false, devices: [], reason: "Intune non configuré ou permissions insuffisantes." };
  }

  const devices = devRaw.value || [];

  if (devices.length === 0) {
    return { available: true, devices: [], reason: "Aucun appareil enrôlé dans Intune." };
  }

  up("Politiques de conformité Intune...");
  const policiesRaw = await gGet("/deviceManagement/deviceCompliancePolicies?$top=50");
  const policies    = policiesRaw?.value || [];

  // ── Calculs ──────────────────────────────────────────────────────────────────
  const compliant    = devices.filter(d => d.complianceState === "compliant");
  const nonCompliant = devices.filter(d => d.complianceState === "noncompliant");
  const unknown      = devices.filter(d => d.complianceState !== "compliant" && d.complianceState !== "noncompliant");

  const complianceRate = devices.length ? Math.round(compliant.length / devices.length * 100) : 0;

  // Chiffrement (isEncrypted — disponible sur Windows/macOS, moins fiable iOS/Android)
  const devWithEncInfo = devices.filter(d => d.isEncrypted !== null && d.isEncrypted !== undefined);
  const encrypted      = devWithEncInfo.filter(d => d.isEncrypted === true);
  const encryptedRate  = devWithEncInfo.length ? Math.round(encrypted.length / devWithEncInfo.length * 100) : 100;

  // OS à jour — heuristique par versions connues
  const osVersionMap = {
    Windows: "10.0.19045", // Win10 22H2 minimum
    iOS:     "17.0",
    Android: "13.0",
    macOS:   "13.0"        // Ventura
  };
  const upToDate = devices.filter(d => {
    const minVer = osVersionMap[d.operatingSystem];
    if (!minVer || !d.osVersion) return true; // inconnu = neutre
    return _compareVersions(d.osVersion, minVer) >= 0;
  });
  const upToDateRate = Math.round(upToDate.length / devices.length * 100);

  // PIN : pas exposé directement — on approxime via complianceState
  // Sur Intune, un appareil conforme a forcément un PIN configuré si la politique l'exige.
  // Sans accès à deviceCompliancePolicyDeviceStateSummary, on se base sur complianceState.
  const pinRate = complianceRate; // même valeur, source de vérité Intune

  // Par plateforme
  const byPlatform = {};
  const osIcons    = { Windows:"🖥", iOS:"📱", Android:"📱", macOS:"💻" };
  devices.forEach(d => {
    const os = d.operatingSystem || "Autre";
    if (!byPlatform[os]) byPlatform[os] = { all:[], compliant:[], noncompliant:[], unknown:[] };
    byPlatform[os].all.push(d);
    if (d.complianceState === "compliant")    byPlatform[os].compliant.push(d);
    else if (d.complianceState === "noncompliant") byPlatform[os].noncompliant.push(d);
    else byPlatform[os].unknown.push(d);
  });

  return {
    available: true,
    devices, policies, compliant, nonCompliant, unknown,
    complianceRate, encryptedRate, pinRate, upToDateRate,
    byPlatform, osIcons
  };
}

function _compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// ── Alertes (dashboard) ────────────────────────────────────────────────────────
function buildIntuneAlerts(d) {
  if (!d.available) return [{ lvl:"gray", msg:"Intune non configuré" }];
  const alerts = [];
  if (d.nonCompliant.length > 0)
    alerts.push({ lvl:"red",    msg: d.nonCompliant.length+" appareil(s) non conformes" });
  if (d.complianceRate < 80)
    alerts.push({ lvl:"orange", msg: "Conformité Intune à "+d.complianceRate+"%" });
  if (d.encryptedRate < 90)
    alerts.push({ lvl:"orange", msg: "Chiffrement activé sur "+d.encryptedRate+"% des appareils" });
  return alerts;
}

// ── Render ─────────────────────────────────────────────────────────────────────
function renderIntunePage(d) {
  _intuneData = d;

  if (!d.available) {
    const mEl = document.getElementById("intune-metrics");
    const pEl = document.getElementById("intune-platforms");
    if (mEl) mEl.innerHTML = `<div class="metric"><div class="metric-lbl">Intune</div><div class="metric-val" style="font-size:1rem;color:var(--text2)">Non disponible</div><div class="metric-sub">${d.reason||""}</div></div>`;
    if (pEl) pEl.innerHTML = `<div class="data-panel" style="padding:1.5rem;text-align:center;color:var(--text2);font-size:.78rem">${d.reason||"Intune non configuré."}</div>`;
    set("cnt-nc", "—");
    sessionStorage.setItem("score-intune", "N/A");
    return;
  }

  const { pts, total } = calcIntuneScore(d);

  // Score ring
  _animateScoreRing(total, "score-circle", "score-num", "score-label", "score-desc");

  // Métriques
  const mEl = document.getElementById("intune-metrics");
  if (mEl) mEl.innerHTML = [
    { lbl:"Total appareils",  val:d.devices.length,    sub:"",                                     cls:"blue" },
    { lbl:"Conformes",        val:d.compliant.length,   sub:d.complianceRate+"%",                   cls:"green" },
    { lbl:"Non conformes",    val:d.nonCompliant.length,sub:d.nonCompliant.length===0?"Aucun":"À corriger", cls:d.nonCompliant.length===0?"green":"red" },
    { lbl:"Inconnus",         val:d.unknown.length,     sub:"",                                     cls:d.unknown.length===0?"green":"orange" },
    { lbl:"Chiffrement",      val:d.encryptedRate+"%",  sub:"Appareils chiffrés",                   cls:d.encryptedRate>=90?"green":d.encryptedRate>=70?"orange":"red" },
    { lbl:"OS à jour",        val:d.upToDateRate+"%",   sub:"Versions récentes",                    cls:d.upToDateRate>=80?"green":d.upToDateRate>=50?"orange":"red" }
  ].map(m => `<div class="metric ${m.cls}"><div class="metric-lbl">${m.lbl}</div><div class="metric-val">${m.val}</div>${m.sub?`<div class="metric-sub">${m.sub}</div>`:""}</div>`).join("");

  // Points d'audit
  const cEl = document.getElementById("intune-checks");
  if (cEl) cEl.innerHTML = [
    { name:"Conformité appareils", desc:d.compliant.length+"/"+d.devices.length+" appareils conformes", pts:pts.compliance, max:30, s:d.complianceRate===100?"green":d.complianceRate>=80?"orange":"red", val:d.complianceRate+"%" },
    { name:"Chiffrement",          desc:"BitLocker / FileVault activé",                                 pts:pts.encryption,  max:25, s:d.encryptedRate>=90?"green":d.encryptedRate>=70?"orange":"red",     val:d.encryptedRate+"%" },
    { name:"PIN / Code d'accès",   desc:"Via stratégie de conformité Intune",                           pts:pts.pin,         max:25, s:d.pinRate>=90?"green":d.pinRate>=70?"orange":"red",                  val:d.pinRate+"%" },
    { name:"OS à jour",            desc:"Versions OS récentes (Win 10.0.19045+, iOS 17+…)",            pts:pts.osUpToDate,  max:20, s:d.upToDateRate>=80?"green":d.upToDateRate>=50?"orange":"red",        val:d.upToDateRate+"%" }
  ].map(_intuneCheckCard).join("");

  // Recommandations
  _renderIntuneRecos(d);

  // Plateformes
  _renderPlatformGrid(d);

  // Table appareils
  _df = { compliance: "all", os: "all" };
  set("cnt-nc", d.devices.length + " total");
  _filterDevicesRender();

  // Injecter les filtres OS dans la filter-bar
  _injectOSTags(d);

  // Cache score
  sessionStorage.setItem("score-intune", total);
  sessionStorage.setItem("alerts-intune", JSON.stringify(buildIntuneAlerts(d)));
  const nb = document.getElementById("nb-intune-score");
  if (nb) nb.textContent = total + "/100";
}

function _renderIntuneRecos(d) {
  const el = document.getElementById("intune-recos");
  if (!el) return;
  const recos = [];
  if (d.nonCompliant.length > 0)
    recos.push({ t:"Appareils non conformes", p:d.nonCompliant.length+" appareil(s) non conformes. Vérifier les politiques de conformité assignées et notifier les utilisateurs.", l:"red" });
  if (d.encryptedRate < 90)
    recos.push({ t:"Chiffrement incomplet", p:"Seulement "+d.encryptedRate+"% des appareils sont chiffrés. Activer BitLocker (Windows) ou FileVault (macOS) via stratégie Intune.", l:"orange" });
  if (d.upToDateRate < 80)
    recos.push({ t:"OS obsolètes", p:d.upToDateRate+"% des appareils ont un OS récent. Configurer des anneaux de mise à jour Windows Update for Business et une politique iOS/Android.", l:"orange" });
  if (d.policies.length === 0)
    recos.push({ t:"Aucune politique de conformité", p:"Aucune stratégie de conformité Intune détectée. Sans politique assignée, les appareils sont marqués conformes par défaut.", l:"red" });
  if (recos.length === 0)
    recos.push({ t:"Configuration satisfaisante", p:"Les appareils Intune sont bien configurés. Maintenir les politiques à jour.", l:"green" });

  el.innerHTML = recos.map(r => `<div class="reco${r.l==="red"?" crit":r.l==="green"?" ok":""}"><h4>${r.l==="green"?"✓":"⚠"} ${r.t}</h4><p>${r.p}</p></div>`).join("");
}

function _renderPlatformGrid(d) {
  const el = document.getElementById("intune-platforms");
  if (!el) return;
  el.innerHTML = `<div class="platform-grid">${
    Object.entries(d.byPlatform).map(([os, info]) => `
      <div class="platform-card" onclick="showPlatformModal('${os}')">
        <div class="pc-top"><span class="pc-os">${d.osIcons[os]||"💾"} ${os}</span><span class="pc-total">${info.all.length}</span></div>
        <div class="pc-stats">
          <div class="pc-stat"><span>Conformes</span><span style="color:var(--green)">${info.compliant.length}</span></div>
          <div class="pc-stat"><span>Non conformes</span><span style="color:${info.noncompliant.length>0?"var(--red)":"var(--green)"}">${info.noncompliant.length}</span></div>
          ${info.unknown.length>0?`<div class="pc-stat"><span>Inconnus</span><span style="color:var(--orange)">${info.unknown.length}</span></div>`:""}
        </div>
      </div>`
    ).join("")}
  </div>`;
}

function _injectOSTags(d) {
  const bar = document.querySelector("#view-devices .filter-bar");
  if (!bar || bar.querySelector("#f-os-tags")) return;
  const sep  = document.createElement("div"); sep.className = "filter-sep";
  const wrap = document.createElement("span"); wrap.id = "f-os-tags";
  wrap.innerHTML = Object.keys(d.byPlatform).map(os =>
    `<span class="ftag" data-group="os" onclick="setDevFilter('os','${os}',this)">${d.osIcons[os]||"💾"} ${os}</span>`
  ).join("");
  const cnt = bar.querySelector(".filter-count");
  if (cnt) { bar.insertBefore(sep, cnt); bar.insertBefore(wrap, cnt); }
}

// ── Filtres UI ─────────────────────────────────────────────────────────────────
function setDevFilter(type, val, el) {
  _df[type] = val;
  el.closest(".filter-bar").querySelectorAll(`.ftag[data-group='${type}']`).forEach(t => t.classList.remove("active"));
  el.classList.add("active");
  _filterDevicesRender();
}

function _filterDevicesRender() {
  if (!_intuneData?.devices) return;
  const q    = (document.getElementById("f-dev-search")?.value || "").toLowerCase();
  const devs = _intuneData.devices.filter(d => {
    if (q && !d.deviceName?.toLowerCase().includes(q) && !d.userDisplayName?.toLowerCase().includes(q) && !d.userPrincipalName?.toLowerCase().includes(q)) return false;
    if (_df.compliance !== "all") {
      if (_df.compliance === "compliant"    && d.complianceState !== "compliant")    return false;
      if (_df.compliance === "noncompliant" && d.complianceState !== "noncompliant") return false;
      if (_df.compliance === "unknown"      && (d.complianceState === "compliant" || d.complianceState === "noncompliant")) return false;
    }
    if (_df.os !== "all" && d.operatingSystem !== _df.os) return false;
    return true;
  });
  set("f-dev-count", devs.length + " résultat(s)");
  const tbl = document.getElementById("tbl-nc");
  if (!tbl) return;
  tbl.innerHTML = devs.map(d => {
    const cs = d.complianceState==="compliant"?"green":d.complianceState==="noncompliant"?"red":"orange";
    const cl = d.complianceState==="compliant"?"Conforme":d.complianceState==="noncompliant"?"Non conforme":"Inconnu";
    const enc = d.isEncrypted===true?"✓":d.isEncrypted===false?"✗":"—";
    return `<tr>
      <td>${d.deviceName||"—"}</td>
      <td>${d.userDisplayName||"—"}</td>
      <td>${d.operatingSystem||"—"}</td>
      <td class="mono">${d.osVersion||"—"}</td>
      <td><span class="pill pill-${cs}"><span class="pill-dot"></span>${cl}</span></td>
      <td style="color:${d.isEncrypted===false?"var(--red)":"inherit"}">${enc}</td>
      <td class="mono">${d.lastSyncDateTime?new Date(d.lastSyncDateTime).toLocaleDateString("fr-FR"):"Jamais"}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="7" class="empty">Aucun résultat</td></tr>';
}

// ── Modal plateforme ───────────────────────────────────────────────────────────
function showPlatformModal(os) {
  const d = _intuneData?.byPlatform?.[os]; if (!d) return;
  document.getElementById("modal-title").textContent = os + " — Appareils";
  document.getElementById("modal-cnt").textContent   = d.all.length + " appareil(s)";
  document.getElementById("modal-body").innerHTML    = d.all.map(dev => `
    <div class="modal-row">
      <div class="mr-main">
        <div class="mr-name">${dev.deviceName||"—"}</div>
        <div class="mr-sub">${dev.userPrincipalName||dev.userDisplayName||"—"}</div>
      </div>
      <div style="display:flex;align-items:center;gap:.6rem">
        <span class="mr-meta">${dev.osVersion||""}</span>
        <span class="pill pill-${dev.complianceState==="compliant"?"green":dev.complianceState==="noncompliant"?"red":"orange"}">
          <span class="pill-dot"></span>${dev.complianceState==="compliant"?"Conforme":dev.complianceState==="noncompliant"?"Non conforme":"Inconnu"}
        </span>
      </div>
    </div>`).join("");
  document.getElementById("modal-overlay").classList.add("active");
}
function closeModal() { document.getElementById("modal-overlay").classList.remove("active"); }

// ── Helpers ────────────────────────────────────────────────────────────────────
function _intuneCheckCard(c) {
  const lbl = c.s==="green"?"OK":c.s==="orange"?"Partiel":c.s==="red"?"Critique":"N/A";
  return `<div class="check-card"><div class="cc-top"><span class="cc-name">${c.name}</span><span class="cc-pts">${c.pts}/${c.max}</span></div><div class="cc-desc">${c.desc}</div><div class="cc-bot"><span class="cc-val">${c.val}</span><span class="pill pill-${c.s}"><span class="pill-dot"></span>${lbl}</span></div></div>`;
}
function _animateScoreRing(score, circleId, numId, labelId, descId) {
  const C = 314;
  const color = score>=80?"#22c55e":score>=60?"#f59e0b":"#ef4444";
  const label = score>=80?"Bon niveau":score>=60?"Niveau moyen":score>=40?"Insuffisant":"Critique";
  const desc  = score>=80?"Conformité satisfaisante.":score>=60?"Améliorations recommandées.":score>=40?"Risques identifiés.":"Action urgente nécessaire.";
  const circle = document.getElementById(circleId);
  if (circle) { setTimeout(() => { circle.style.strokeDashoffset = C - (score/100)*C; }, 60); circle.style.stroke = color; }
  const numEl = document.getElementById(numId); if (numEl) { numEl.textContent = score; numEl.style.color = color; }
  const lblEl = document.getElementById(labelId); if (lblEl) { lblEl.textContent = label; lblEl.style.cssText = `color:${color};background:${color}18`; }
  if (descId) set(descId, desc);
}

// ── Point d'entrée ─────────────────────────────────────────────────────────────
async function runIntuneAudit(updateFn) {
  const data = await fetchIntuneData(updateFn);
  _intuneData = data;
  renderIntunePage(data);
  return { score: calcIntuneScore(data).total, alerts: buildIntuneAlerts(data), data };
}
