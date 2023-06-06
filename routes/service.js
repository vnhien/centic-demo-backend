const express = require("express");
const { verifyTk } = require("../middleware/auth");
const { getDBConnection } = require("../db/connect");
const router = express.Router();
const { v4: uuidv4 } = require("uuid");
const { verifyApiKey } = require("../function/service");
const Crypto = require("crypto-js");
const jwt = require("jsonwebtoken");

router.post("/createKey", verifyTk, async (req, res) => {
  try {
    const { userData } = req;
    const { condition, operator, keyName } = req.body;
    const db = await getDBConnection();
    const collection = db.collection("centic-services-api-keys");
    const nodeCrypto = require("crypto");
    const prefix = nodeCrypto.randomBytes(8).toString("hex");
    const newApiKey = nodeCrypto.randomBytes(16).toString("hex");
    const encryptedKey = await Crypto.AES.encrypt(
      newApiKey,
      process.env.ENCRYPTKEY
    ).toString();
    const updatedResult = collection.insertOne({
      key_id: prefix,
      key: encryptedKey,
      userId: userData.userId,
      scope: "all",
      status: "active",
      condition: condition,
      operator: operator,
      keyName: keyName,
      createDate: Date.now(),
    });
    res.json({
      key: prefix + "." + newApiKey,
      success: true,
    });
  } catch (err) {
    res.json({
      success: false,
      err: err.message,
    });
  }
});
router.get("/getAllKey", verifyTk, async (req, res) => {
  try {
    const { userData } = req;
    const db = await getDBConnection();
    const collection = db.collection("centic-services-api-keys");
    const userId = userData.userId;
    const allKeyData = (
      await collection.find({ userId: userId }).toArray()
    ).map((item) => {
      return {
        key_id: item["key_id"],
        name: item.keyName,
        condition: item.condition,
        operator: item.operator,
        createDate: item.createDate,
        status: item.status,
      };
    });
    res.status(200);
    res.send(allKeyData);
  } catch (err) {
    res.status(400);
    res.send(err.message);
  }
});
router.get("/getKey", verifyTk, async (req, res) => {
  try {
    const { key_id } = req.query;
    const db = await getDBConnection();
    const collection = db.collection("centic-services-api-keys");
    const keyData = await collection.findOne({ key_id: key_id });
    const keyDecrypted = Crypto.AES.decrypt(
      keyData.key,
      process.env.ENCRYPTKEY
    ).toString(Crypto.enc.Utf8);
    res.json({ key: key_id + "." + keyDecrypted, success: true });
  } catch (err) {
    res.json({ success: false, err: err.message });
  }
});
router.post("/verifyKey", verifyApiKey, (req, res) => {
  res.send("ok");
});
router.post("/revokeKey", verifyTk, async (req, res) => {
  try {
    const { key_id } = req.body;
    if (!key_id) {
      res.status(400);
      res.json({ success: false, message: "No key" });
      res.end();
    }
    const db = await getDBConnection();
    const collection = db.collection("centic-services-api-keys");
    await collection.findOneAndUpdate(
      { key_id: key_id },
      {
        $set: {
          status: "revoked",
        },
      }
    );
    res.status(200);
    res.json({
      success: true,
    });
  } catch (err) {
    res.status(400);
    res.json({ success: false, message: err.message });
  }
});

router.get("/createUrl", verifyApiKey, async (req, res) => {
  try {
    const apiKey_id = req.header("x-apikey").split(".")[0];
    const { web2Id } = req.query;
    const token = jwt.sign(
      {
        web2Id: web2Id,
        key_id: apiKey_id,
      },
      process.env.SECRET_KEY,
      { expiresIn: 600 }
    );
    const db = await getDBConnection();
    const keyCollection = db.collection("centic-services-api-keys");
    const userCollection = db.collection("centic-services-user");
    const userKeyData = await keyCollection.findOne({
      key_id: apiKey_id,
    });
    const bankId = (
      await userCollection.findOne({
        id: userKeyData.userId,
      })
    )?.bankId;
    const condition = userKeyData.condition;
    res.json({
      url: `http://172.168.15.92:3000/?token=${token}&thirdPartyID=${bankId}&web2ID=${web2Id}&condition=${condition}`,
    });
  } catch (err) {
    console.log(err.message);
    res.status(400);
    res.end(err.message);
  }
});
router.post("/verifyUrl", async (req, res) => {
  const { app_url } = req.body;
  const url = require("url");
  const token = url.parse(app_url).query;
  const queryString = require("node:querystring");
  const tempToken = queryString.decode(token).token;
  if (!tempToken) {
    res.status(400);
    res.json({ valid: false, message: "no token" });
    return;
  }
  try {
    const result = await jwt.verify(tempToken, process.env.SECRET_KEY);
    res.status(200);
    res.json({
      valid: true,
    });
  } catch (err) {
    res.status(400);
    res.json({ valid: false, message: err.message });
    return;
  }
});

module.exports = router;
