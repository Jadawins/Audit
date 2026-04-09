"use strict";
const pino = require("pino");

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  base: { service: "auditms-api" },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ["body.client_secret", "req.headers.authorization"],
    censor: "[REDACTED]"
  }
});

module.exports = logger;
