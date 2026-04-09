/* =========================================================
   LEAD-FORM.JS — Composant lead generation réutilisable
   Injecte : alarm-banner, low-score-banner, CTA flottant,
             modal formulaire de contact
   Usage   : initLeadForm({ score, alerts, details, module })
   ========================================================= */

(function () {
  "use strict";

  // ── Texte alarmiste selon score ────────────────────────────
  function _alarmText(score) {
    if (score > 70)
      return "Votre tenant présente des vulnérabilités connues susceptibles d'être exploitées par des acteurs malveillants.";
    if (score > 50)
      return "Plusieurs failles de sécurité ont été identifiées. Vos données peuvent être exposées.";
    return "Votre environnement présente un risque élevé de compromission. Une action immédiate est recommandée.";
  }

  // ── Remplir les bannières + CTA ────────────────────────────
  function _renderBanners(score, alerts) {
    // Bannière score critique
    const lowEl = document.getElementById("lead-low-score-banner");
    if (lowEl) {
      if (score < 50) {
        lowEl.innerHTML = `<div class="low-score-banner">⚠ Score critique : ${score}/100 — Votre environnement Microsoft 365 est exposé à des risques immédiats.</div>`;
        lowEl.style.display = "block";
      } else {
        lowEl.style.display = "none";
      }
    }

    // Bannière alarmes
    const alarmEl = document.getElementById("lead-alarm-banner");
    if (alarmEl) {
      const cls = score < 50 ? "alarm-red" : "alarm-orange";
      let html = `<div class="alarm-banner ${cls}">`;
      html += `<div class="alarm-text">${_alarmText(score)}</div>`;
      if (alerts && alerts.length) {
        html += `<ul class="alarm-list">`;
        alerts.forEach(a => {
          html += `<li class="alarm-item alarm-item-${a.lvl}"><span class="alarm-dot alarm-dot-${a.lvl}"></span>${a.msg}</li>`;
        });
        html += `</ul>`;
      }
      html += `</div>`;
      alarmEl.innerHTML = html;
    }

    // Bouton CTA flottant
    const ctaEl = document.getElementById("lead-cta");
    if (ctaEl) {
      const urgent = score < 50;
      ctaEl.innerHTML = `<button class="lead-cta-btn${urgent ? " lead-cta-urgent" : ""}" onclick="openLeadModal()">
        <span class="lead-cta-icon">↗</span> Améliorer mon score
      </button>`;
    }
  }

  // ── Injecter le modal dans le DOM (une seule fois) ─────────
  function _injectModal() {
    if (document.getElementById("lead-modal-overlay")) return;
    const el = document.createElement("div");
    el.id        = "lead-modal-overlay";
    el.className = "modal-overlay";
    el.innerHTML = `
      <div class="modal" style="max-width:520px">
        <div class="modal-head">
          <h3>Améliorer votre score Microsoft 365</h3>
          <button class="modal-x" onclick="closeLeadModal()">✕</button>
        </div>
        <div class="modal-body" style="padding:1.5rem">
          <div id="lead-modal-form">
            <p style="font-size:.8rem;color:var(--text2);margin-bottom:1.25rem;line-height:1.6">
              Nos experts analysent vos résultats et vous recontactent sous 24h avec un plan d'action personnalisé.
            </p>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:.65rem">
              <input class="lead-form-input" id="lf-prenom"    placeholder="Prénom *">
              <input class="lead-form-input" id="lf-nom"       placeholder="Nom *">
              <input class="lead-form-input" id="lf-societe"   placeholder="Société" style="grid-column:1/-1">
              <input class="lead-form-input" id="lf-email"     placeholder="Email professionnel *" type="email" style="grid-column:1/-1">
              <input class="lead-form-input" id="lf-telephone" placeholder="Téléphone" style="grid-column:1/-1">
              <textarea class="lead-form-input" id="lf-commentaire" placeholder="Message (facultatif)" rows="3" style="grid-column:1/-1;resize:vertical"></textarea>
            </div>
            <div class="error-msg" id="lf-error" style="margin-top:.75rem;display:none"></div>
            <div style="display:flex;justify-content:flex-end;margin-top:1rem">
              <button class="btn btn-primary" id="lf-submit-btn" style="width:auto;padding:.6rem 1.75rem" onclick="submitLead()">
                Envoyer la demande
              </button>
            </div>
            <p style="font-size:.65rem;color:var(--text2);margin-top:.75rem;text-align:center">
              Vos données ne sont transmises qu'à REEL IT et ne sont jamais revendues.
            </p>
          </div>
          <div id="lead-modal-success" style="display:none;text-align:center;padding:2.5rem 1rem">
            <div style="font-size:2.5rem;margin-bottom:.75rem;color:var(--green)">✓</div>
            <p style="font-size:.95rem;font-weight:500;margin-bottom:.4rem">Demande envoyée !</p>
            <p style="font-size:.8rem;color:var(--text2)">Nous reviendrons vers vous rapidement.</p>
          </div>
        </div>
      </div>`;
    document.body.appendChild(el);
    el.addEventListener("click", e => { if (e.target === el) closeLeadModal(); });
  }

  // ── Contexte partagé entre les fonctions globales ──────────
  let _ctx = {};

  // ── Fonctions exposées globalement ─────────────────────────
  window.openLeadModal = function () {
    document.getElementById("lead-modal-overlay")?.classList.add("active");
    document.getElementById("lead-modal-form").style.display   = "";
    document.getElementById("lead-modal-success").style.display = "none";
    const err = document.getElementById("lf-error");
    if (err) { err.textContent = ""; err.style.display = "none"; }
  };

  window.closeLeadModal = function () {
    document.getElementById("lead-modal-overlay")?.classList.remove("active");
  };

  window.submitLead = async function () {
    const prenom      = document.getElementById("lf-prenom")?.value.trim()      || "";
    const nom         = document.getElementById("lf-nom")?.value.trim()          || "";
    const societe     = document.getElementById("lf-societe")?.value.trim()      || null;
    const email       = document.getElementById("lf-email")?.value.trim()        || "";
    const telephone   = document.getElementById("lf-telephone")?.value.trim()    || null;
    const commentaire = document.getElementById("lf-commentaire")?.value.trim()  || null;
    const errEl       = document.getElementById("lf-error");
    const btn         = document.getElementById("lf-submit-btn");

    if (!prenom || !nom || !email) {
      errEl.textContent = "Prénom, nom et email sont obligatoires.";
      errEl.style.display = "block";
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errEl.textContent = "Adresse email invalide.";
      errEl.style.display = "block";
      return;
    }
    errEl.style.display = "none";
    if (btn) { btn.disabled = true; btn.textContent = "Envoi en cours..."; }

    try {
      const res = await fetch("https://auditms.fr/api/lead", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prenom, nom,
          societe:     societe     || null,
          email,
          telephone:   telephone   || null,
          commentaire: commentaire || null,
          scores:      _ctx.scores  || null,
          alerts:      _ctx.alerts  || null,
          details:     _ctx.details || null
        })
      });
      if (!res.ok) throw new Error("Erreur " + res.status);
      document.getElementById("lead-modal-form").style.display    = "none";
      document.getElementById("lead-modal-success").style.display = "";
    } catch {
      errEl.textContent = "Impossible d'envoyer. Réessayez dans quelques instants.";
      errEl.style.display = "block";
      if (btn) { btn.disabled = false; btn.textContent = "Envoyer la demande"; }
    }
  };

  // ── Point d'entrée public ──────────────────────────────────
  window.initLeadForm = function ({ score, alerts, details, module: mod }) {
    _ctx = { scores: { [mod]: score }, alerts, details };
    _injectModal();
    _renderBanners(score, alerts);
  };
})();
