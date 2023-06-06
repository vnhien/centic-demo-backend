const { MongoClient } = require("mongodb");
const comgooes = require("mongoose");

const userName = "admin";
const password = "admin";

const connectString = `mongodb+srv://${userName}:${password}@centicservice.nvp4gl0.mongodb.net/?retryWrites=true&w=majority`;
// const connectString =
//   " mongodb+srv://centic:centic%40123@cluster0.kwlxc.mongodb.net/admin?authSource=admin&replicaSet=atlas-aug2p6-shard-0&readPreference=primary&appname=MongoDB%20Compass&ssl=true";
const client = new MongoClient(connectString);

const getDBConnection = async () => {
  await client.connect();
  const db = client.db("centic");
  return db;
};
module.exports = { getDBConnection };
