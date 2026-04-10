/* =========================================================
   SERVER.JS — API Leads + Deploy Webhook
   Port 3001 · géré par PM2
   ========================================================= */

"use strict";
require("dotenv").config({ path: __dirname + "/../shared/.env" });
const express    = require("express");
const nodemailer = require("nodemailer");
const path       = require("path");
const https      = require("https");
const { execSync } = require("child_process");
const rateLimit  = require("express-rate-limit");
const { LeadSchema, InboxRulesSchema } = require("./validation");
const logger     = require("./logger");
const { saveLead } = require("./db");
const metrics    = require("./metrics");

const app  = express();
const PORT = 3001;

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(express.json());
app.use((req, res, next) => {
  const allowed = ["https://auditms.fr", "https://www.auditms.fr"];
  const origin  = req.headers.origin;
  if (!origin || allowed.includes(origin) || origin.startsWith("http://localhost")) {
    if (origin) res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ── Logging des requêtes ───────────────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    logger.info({
      method: req.method,
      path:   req.path,
      status: res.statusCode,
      ms:     Date.now() - start,
      ip:     req.headers["x-forwarded-for"] || req.socket.remoteAddress
    });
  });
  next();
});

// ── Rate limiters ──────────────────────────────────────────────────────────────
const leadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de demandes, réessayez dans 15 minutes." }
});

const graphLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Limite de requêtes dépassée, réessayez dans 1 minute." }
});

// ── Config ─────────────────────────────────────────────────────────────────────
const CLIENT_ID     = process.env.AZURE_CLIENT_ID     || "bd7f8225-61af-4ac0-bc6c-aaccd6a22fac";
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET || "";
const SMTP_HOST     = process.env.SMTP_HOST     || "mail.auditms.fr";
const SMTP_PORT_NUM = parseInt(process.env.SMTP_PORT) || 587;
const SMTP_USER     = process.env.SMTP_USER     || "no-reply@auditms.fr";
const SMTP_PASS     = process.env.SMTP_PASS     || "";
const LEAD_DEST     = process.env.LEAD_DEST     || "william@auditms.fr";
const DEPLOY_SECRET = process.env.WEBHOOK_SECRET || "";
const APP_DIR       = process.env.APP_DIR       || "/var/www/auditms/app";

// Vérification des variables critiques au démarrage
if (!DEPLOY_SECRET) {
  logger.fatal("WEBHOOK_SECRET non défini — arrêt du serveur.");
  process.exit(1);
}

// ── Graph API (client_credentials) ────────────────────────────────────────────
async function _getAppToken(tenantId) {
  const body = new URLSearchParams({
    grant_type:    "client_credentials",
    client_id:     CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope:         "https://graph.microsoft.com/.default"
  }).toString();

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: "login.microsoftonline.com",
      path:     `/${tenantId}/oauth2/v2.0/token`,
      method:   "POST",
      headers:  { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) }
    }, res => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { const j = JSON.parse(data); j.access_token ? resolve(j.access_token) : reject(new Error(j.error_description || "Token error")); }
        catch(e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function _graphGet(token, path) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: "graph.microsoft.com",
      path:     path.startsWith("/") ? "/v1.0" + path : path,
      method:   "GET",
      headers:  { Authorization: "Bearer " + token, Accept: "application/json" }
    }, res => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try {
          const j = JSON.parse(data);
          if (res.statusCode === 403 || res.statusCode === 404) resolve(null);
          else if (res.statusCode >= 400) reject(new Error("Graph " + res.statusCode + " — " + path));
          else resolve(j);
        } catch(e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

// ── GET /healthz ───────────────────────────────────────────────────────────────
app.get("/healthz", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), ts: new Date().toISOString() });
});

// ── GET /metrics ───────────────────────────────────────────────────────────────
app.get("/metrics", (req, res) => {
  const token = req.headers["x-metrics-token"];
  if (process.env.METRICS_TOKEN && token !== process.env.METRICS_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  res.json(metrics.get());
});

// ── POST /api/inbox-rules ──────────────────────────────────────────────────────
app.post("/inbox-rules", graphLimiter, async (req, res) => {
  try {
    if (!CLIENT_SECRET) return res.status(503).json({ error: "Client secret non configuré" });

    const parsed = InboxRulesSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Données invalides", details: parsed.error.flatten() });
    const { tenantId, users } = parsed.data;

    const token   = await _getAppToken(tenantId);
    const results = [];

    for (let i = 0; i < users.length; i++) {
      const u = users[i];
      // Pause anti-throttling toutes les 10 requêtes
      if (i > 0 && i % 10 === 0) await new Promise(r => setTimeout(r, 200));
      try {
        const data = await _graphGet(token, "/users/" + u.id + "/mailFolders/inbox/messageRules");
        if (!data) continue;
        const rules = data.value || [];
        const flagged = rules.filter(r => {
          const a = r.actions || {};
          return a.delete === true ||
            a.forwardTo?.some(f => f.emailAddress?.address) ||
            a.forwardAsAttachmentTo?.some(f => f.emailAddress?.address) ||
            a.redirectTo?.some(f => f.emailAddress?.address) ||
            (a.markAsRead && a.moveToFolder);
        });
        flagged.forEach(r => {
          const a = r.actions || {};
          const flags = [];
          if (a.delete) flags.push("Suppression silencieuse");
          if (a.forwardTo?.length) flags.push("Transfert: " + a.forwardTo.map(f => f.emailAddress?.address).join(", "));
          if (a.redirectTo?.length) flags.push("Redirection: " + a.redirectTo.map(f => f.emailAddress?.address).join(", "));
          if (a.markAsRead && a.moveToFolder) flags.push("Lu+Déplacer");
          results.push({ userId: u.id, displayName: u.displayName, upn: u.userPrincipalName, ruleName: r.displayName, flags });
        });
      } catch {}
    }

    metrics.inc("graph_calls");
    res.json({ results });
  } catch (e) {
    metrics.inc("graph_errors");
    logger.error({ err: e.message }, "inbox-rules error");
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/lead ─────────────────────────────────────────────────────────────
app.post("/lead", leadLimiter, async (req, res) => {
  try {
    const parsed = LeadSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Données invalides", details: parsed.error.flatten() });
    const { prenom, nom, societe, email, telephone, commentaire, scores, alerts, details } = parsed.data;

    // 1. Sauvegarde en base MongoDB
    const lead = {
      prenom, nom, societe, email, telephone, commentaire, scores, alerts,
      ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress
    };
    await saveLead(lead);

    // 2. Email via SMTP Zimbra
    if (SMTP_PASS) {
      try {
        const transporter = nodemailer.createTransport({
          host: SMTP_HOST, port: SMTP_PORT_NUM, secure: false,
          auth: { user: SMTP_USER, pass: SMTP_PASS },
          tls:  { rejectUnauthorized: false }
        });

        // Formatage scores
        const scoreEmoji = s => s >= 80 ? "✓" : s >= 60 ? "~" : "⚠";
        const scoresText = scores
          ? Object.entries(scores).map(([k, v]) => `  ${k.padEnd(16)}: ${v}/100 ${scoreEmoji(v)}`).join("\n")
          : "  Non calculés";

        // Formatage alertes
        const alertsText = alerts && alerts.length
          ? alerts.map(a => `  ${a.lvl === "red" ? "🔴" : "🟡"} ${a.msg}`).join("\n")
          : "  Aucune alerte";

        // Détails techniques complets
        let detailsText = "";
        if (details) {
          const lines = ["\n\n═══════════════════════════════", "DÉTAILS TECHNIQUES (confidentiel)", "═══════════════════════════════"];
          if (details.noMfaUsers?.length)
            lines.push(`\nSans MFA (${details.noMfaUsers.length}) :`, ...details.noMfaUsers.map(u => `  - ${u.name} <${u.upn}>`));
          if (details.weakMfaUsers?.length)
            lines.push(`\nMFA faible (${details.weakMfaUsers.length}) :`, ...details.weakMfaUsers.map(u => `  - ${u.name} <${u.upn}>`));
          if (details.inactiveUsers?.length)
            lines.push(`\nComptes inactifs >90j (${details.inactiveUsers.length}) :`, ...details.inactiveUsers.map(u => `  - ${u.name} <${u.upn}>`));
          if (details.globalAdmins?.length)
            lines.push(`\nAdmins globaux (${details.globalAdmins.length}) :`, ...details.globalAdmins.map(u => `  - ${u.name} <${u.upn}>`));
          if (details.nonCompliant?.length)
            lines.push(`\nAppareils non conformes (${details.nonCompliant.length}) :`, ...details.nonCompliant.map(d => `  - ${d.name} — ${d.user} (${d.os})`));
          if (details.wastedLicenses?.length)
            lines.push(`\nLicences gaspillées (${details.wastedLicenses.length}) :`, ...details.wastedLicenses.map(u => `  - ${u.name} <${u.upn}> — ${u.reason}`));
          if (details.inboxRules?.length)
            lines.push(`\nRègles inbox suspectes (${details.inboxRules.length}) :`, ...details.inboxRules.map(r => `  - ${r.name} <${r.upn}> : ${r.rule} → ${(r.flags || []).join(", ")}`));
          if (details.riskyOAuthApps?.length)
            lines.push(`\nApps OAuth à risque (${details.riskyOAuthApps.length}) :`, ...details.riskyOAuthApps.map(a => `  - ${a.app} (${a.publisher}) — ${a.risk?.toUpperCase()} — ${(a.scopes || []).join(", ")}`));
          if (details.adminsWithMailbox?.length)
            lines.push(`\nAdmins sans compte dédié (${details.adminsWithMailbox.length}) :`, ...details.adminsWithMailbox.map(a => `  - ${a.name} <${a.upn}>`));
          detailsText = lines.join("\n");
        }

        await transporter.sendMail({
          from:    `"Audit MS" <${SMTP_USER}>`,
          to:      LEAD_DEST,
          subject: `🎯 Lead — ${prenom} ${nom}${societe ? " (" + societe + ")" : ""}`,
          text: [
            `NOUVEAU LEAD — AuditMS`,
            `═══════════════════════════════`,
            ``,
            `CONTACT`,
            `───────`,
            `Prénom    : ${prenom} ${nom}`,
            `Société   : ${societe || "—"}`,
            `Email     : ${email}`,
            `Téléphone : ${telephone || "—"}`,
            commentaire ? `Message   : ${commentaire}` : null,
            ``,
            `SCORES`,
            `──────`,
            scoresText,
            ``,
            `ALERTES`,
            `───────`,
            alertsText,
            detailsText,
            ``,
            `───────`,
            `Date : ${new Date().toISOString()}`,
            `IP   : ${lead.ip}`
          ].filter(l => l !== null).join("\n")
        });
      } catch (mailErr) {
        metrics.inc("email_errors");
        logger.error({ err: mailErr.message }, "Email error");
      }
    }

    metrics.inc("lead_total");
    res.json({ success: true });
  } catch (e) {
    metrics.inc("lead_errors");
    logger.error({ err: e.message }, "Lead error");
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/deploy — webhook déploiement ────────────────────────────────────
app.post("/deploy", (req, res) => {
  const authHeader = req.headers.authorization || "";
  if (!DEPLOY_SECRET || authHeader !== "Bearer " + DEPLOY_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  res.json({ success: true, message: "Deploy triggered" });
  setTimeout(() => {
    try {
      execSync(`cd ${APP_DIR} && git pull origin main && npm install --omit=dev && node scripts/inject-hashes.js && pm2 reload all 2>&1`, { timeout: 60000 });
      logger.info("Deploy terminé avec succès");
    } catch (e) {
      logger.error({ err: e.message }, "Deploy échoué");
    }
  }, 100);
});

// ── 404 ────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Route inconnue" });
});

// ── Erreur globale ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error({ err: err.message, method: req.method, path: req.path }, "Unhandled error");
  res.status(err.status || 500).json({ error: process.env.NODE_ENV === "production" ? "Erreur interne" : err.message });
});

app.listen(PORT, () => logger.info(`Audit API on port ${PORT}`));
