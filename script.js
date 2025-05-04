const jwt = require("jsonwebtoken");
const crypto = require("crypto");


const JWT_SECRET = "your_jwt_secret";
const ENCRYPTION_KEY = crypto.randomBytes(32);
const IV = crypto.randomBytes(16); 


const encrypt = (payload) => {

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });


  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, "utf8", "hex");
  encrypted += cipher.final("hex");

  return `${IV.toString("hex")}:${encrypted}`;
};


const decrypt = (encryptedToken) => {
  const [ivHex, encrypted] = encryptedToken.split(":");
  const iv = Buffer.from(ivHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");

  const decoded = jwt.verify(decrypted, JWT_SECRET);
  return decoded;
};

module.exports = {
  encrypt,
  decrypt,
};
