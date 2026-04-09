"use strict";
const { MongoClient } = require("mongodb");
const logger = require("./logger");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME     = "auditms";

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

module.exports = { connect, saveLead };
