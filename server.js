/* =========================================================
   SERVER.JS — API Leads + Deploy Webhook
   Port 3001 · géré par PM2
   ========================================================= */

"use strict";
const express    = require("express");
const nodemailer = require("nodemailer");
const fs         = require("fs");
const path       = require("path");
const { execSync } = require("child_process");

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

// ── Config ─────────────────────────────────────────────────────────────────────
const LEADS_FILE    = path.join(__dirname, "leads.json");
const SMTP_HOST     = process.env.SMTP_HOST     || "mail.auditms.fr";
const SMTP_PORT_NUM = parseInt(process.env.SMTP_PORT) || 587;
const SMTP_USER     = process.env.SMTP_USER     || "no-reply@auditms.fr";
const SMTP_PASS     = process.env.SMTP_PASS     || "";
const LEAD_DEST     = process.env.LEAD_DEST     || "william@auditms.fr";
const DEPLOY_SECRET = process.env.WEBHOOK_SECRET || "";
const APP_DIR       = process.env.APP_DIR       || "/var/www/auditms/app";

// ── POST /api/lead ─────────────────────────────────────────────────────────────
app.post("/api/lead", async (req, res) => {
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
    execSync(`cd ${APP_DIR} && git pull origin main 2>&1`, { timeout: 30000 });
    res.json({ success: true, message: "Deployed" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Audit API on port ${PORT}`));
