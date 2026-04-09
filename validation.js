"use strict";
const { z } = require("zod");

const LeadSchema = z.object({
  prenom:      z.string().min(1).max(100).trim(),
  nom:         z.string().min(1).max(100).trim(),
  email:       z.string().email().max(254).trim().toLowerCase(),
  societe:     z.string().max(200).trim().optional().nullable(),
  telephone:   z.string().max(30).trim().optional().nullable(),
  commentaire: z.string().max(1000).trim().optional().nullable(),
  scores:      z.record(z.string(), z.number().min(0).max(100)).optional().nullable(),
  alerts:      z.array(z.object({ lvl: z.string(), msg: z.string() })).max(50).optional().nullable(),
  details:     z.record(z.string(), z.any()).optional().nullable()
});

const InboxRulesSchema = z.object({
  tenantId: z.string().uuid(),
  users:    z.array(z.object({
    id:                z.string(),
    displayName:       z.string().optional(),
    userPrincipalName: z.string().optional()
  })).max(1000)
});

module.exports = { LeadSchema, InboxRulesSchema };
