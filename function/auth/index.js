const jwt = require("jsonwebtoken");

const verifyToken = async (token) => {
  try {
    const res = await jwt.verify(token, process.env.SECRET_KEY);
    return {
      ...res,
      valid: true,
    };
  } catch (errr) {
    return {
      valid: false,
    };
  }
};
const hashString = (message) => {
  const Crypto = require("crypto-js");
  return Crypto.SHA256("test").toString(Crypto.enc.Hex);
};
const verifyHash = (message, hash) => {
  return hash === hashString(message);
};

module.exports = { hashString, verifyHash, verifyToken };
