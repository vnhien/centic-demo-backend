var express = require("express");
var router = express.Router();
const { v4: uuidv4 } = require("uuid");
const { getDBConnection } = require("../db/connect");
const { hashString, verifyHash, verifyToken } = require("../function/auth");
const { verifyTk } = require("../middleware/auth");

router.post("/register", async (req, res) => {
  try {
    const userId = uuidv4();
    const { bankId, password, userName } = req.body;
    if (!(bankId && password && userName)) {
      res.json({ success: false });
      return;
    }
    const db = await getDBConnection();
    const userCollection = db.collection("centic-services-user");
    await userCollection.insertOne({
      userName: userName,
      id: userId,
      bankId: bankId,
      password: hashString(password),
    });
    res.json({
      success: true,
    });
    return;
  } catch (err) {
    res.json({
      success: false,
    });
  }
});
router.post("/login", async (req, res) => {
  const { userName, password } = req.body;
  if (!(userName && password)) {
    res.status(400);
    res.json({
      success: false,
      message: "In valid credential",
    });
  }
  try {
    const db = await getDBConnection();
    const userCollection = db.collection("centic-services-user");
    const userData = await userCollection.findOne({
      userName: userName,
    });
    if (!userData) {
      res.end("user not exist");
      return;
    }
    if (verifyHash(userData.password, password)) {
      res.end("wrong password");
      return;
    }
    var jwt = require("jsonwebtoken");
    var token = jwt.sign(
      {
        userId: userData.id,
        bankId: userData.bankId,
      },
      process.env.SECRET_KEY,
      {
        expiresIn: "30d",
      }
    );
    res.status(200);
    res.json({ token: token });
    return;
  } catch (err) {
    res.status(400);
    res.end(err.message);
  }
});
router.get("/verifyToken", verifyTk, async (req, res) => {
  res.status(200);
  res.json({
    valid: true,
  });
});

module.exports = router;
