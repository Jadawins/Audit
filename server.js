/* =========================================================
   SERVER.JS — API Leads + Deploy Webhook
   Port 3001 · géré par PM2
   ========================================================= */

"use strict";
const express    = require("express");
const nodemailer = require("nodemailer");
const fs         = require("fs");
const path       = require("path");
const https      = require("https");
const { execSync } = require("child_process");
const rateLimit  = require("express-rate-limit");

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
const LEADS_FILE    = path.join(__dirname, "leads.json");
const CLIENT_ID     = process.env.AZURE_CLIENT_ID     || "bd7f8225-61af-4ac0-bc6c-aaccd6a22fac";
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET || "";
const SMTP_HOST     = process.env.SMTP_HOST     || "mail.auditms.fr";
const SMTP_PORT_NUM = parseInt(process.env.SMTP_PORT) || 587;
const SMTP_USER     = process.env.SMTP_USER     || "no-reply@auditms.fr";
const SMTP_PASS     = process.env.SMTP_PASS     || "";
const LEAD_DEST     = process.env.LEAD_DEST     || "william@auditms.fr";
const DEPLOY_SECRET = process.env.WEBHOOK_SECRET || "";
const APP_DIR       = process.env.APP_DIR       || "/var/www/auditms/app";

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

// ── POST /api/inbox-rules ──────────────────────────────────────────────────────
app.post("/api/inbox-rules", graphLimiter, async (req, res) => {
  try {
    if (!CLIENT_SECRET) return res.status(503).json({ error: "Client secret non configuré" });

    const { tenantId, users } = req.body;
    if (!tenantId || !Array.isArray(users)) return res.status(400).json({ error: "tenantId et users requis" });

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

    res.json({ results });
  } catch (e) {
    console.error("inbox-rules error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/lead ─────────────────────────────────────────────────────────────
app.post("/api/lead", leadLimiter, async (req, res) => {
  try {
    const { prenom, nom, societe, email, telephone, scores } = req.body;
    if (!email || !prenom) return res.status(400).json({ error: "Champs requis manquants" });

    // 1. Append dans leads.json
    const lead = {
      prenom, nom, societe, email, telephone, scores,
      ip:   req.headers["x-forwarded-for"] || req.socket.remoteAddress,
      date: new Date().toISOString()
    };
    let leads = [];
    try { if (fs.existsSync(LEADS_FILE)) leads = JSON.parse(fs.readFileSync(LEADS_FILE, "utf8")); } catch {}
    leads.push(lead);
    fs.writeFileSync(LEADS_FILE, JSON.stringify(leads, null, 2));

    // 2. Email via SMTP Zimbra
    if (SMTP_PASS) {
      try {
        const transporter = nodemailer.createTransport({
          host: SMTP_HOST, port: SMTP_PORT_NUM, secure: false,
          auth: { user: SMTP_USER, pass: SMTP_PASS },
          tls:  { rejectUnauthorized: false }
        });
        const scoresText = scores
          ? Object.entries(scores).map(([k, v]) => `${k}: ${v}/100`).join("\n")
          : "Non calculés";
        await transporter.sendMail({
          from:    `"Audit MS" <${SMTP_USER}>`,
          to:      LEAD_DEST,
          subject: `🎯 Nouveau lead — ${prenom} ${nom} (${societe || "?"})`,
          text:    [
            `Nouveau lead Audit MS`,
            ``,
            `Nom       : ${prenom} ${nom}`,
            `Société   : ${societe || "—"}`,
            `Email     : ${email}`,
            `Téléphone : ${telephone || "—"}`,
            ``,
            `Scores :`,
            scoresText,
            ``,
            `Date : ${lead.date}`
          ].join("\n")
        });
      } catch (mailErr) {
        console.error("Email error:", mailErr.message);
        // Ne pas faire échouer la requête si l'email plante
      }
    }

    res.json({ success: true });
  } catch (e) {
    console.error("Lead error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/deploy — webhook déploiement ────────────────────────────────────
app.post("/api/deploy", (req, res) => {
  const authHeader = req.headers.authorization || "";
  if (!DEPLOY_SECRET || authHeader !== "Bearer " + DEPLOY_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    execSync(`cd ${APP_DIR} && git pull origin main && npm install --omit=dev 2>&1`, { timeout: 60000 });
    res.json({ success: true, message: "Deployed" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Audit API on port ${PORT}`));
