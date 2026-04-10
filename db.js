"use strict";
const { MongoClient, ObjectId } = require("mongodb");
const logger = require("./logger");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME     = "audit";

let client;
let db;

async function connect() {
  if (db) return db;
  if (!MONGODB_URI) {
    logger.warn("MONGODB_URI non défini — leads stockés nulle part");
    return null;
  }
  client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db(DB_NAME);
  // TTL index : suppression automatique après 7 jours
  await db.collection("leads").createIndex({ createdAt: 1 }, { expireAfterSeconds: 7 * 24 * 3600, background: true });
  logger.info("MongoDB connecté");
  return db;
}

async function saveLead(lead) {
  const database = await connect();
  if (!database) return null;
  const result = await database.collection("leads").insertOne({
    ...lead,
    createdAt: new Date()
  });
  return result.insertedId;
}

async function getLeads({ limit = 50, skip = 0 } = {}) {
  const database = await connect();
  if (!database) return [];
  return database.collection("leads")
    .find({})
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .toArray();
}

async function deleteLead(id) {
  const database = await connect();
  if (!database) return false;
  const result = await database.collection("leads").deleteOne({ _id: new ObjectId(id) });
  return result.deletedCount === 1;
}

module.exports = { connect, saveLead, getLeads, deleteLead };
