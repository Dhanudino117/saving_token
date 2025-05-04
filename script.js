const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// Replace with your actual secret keys
const JWT_SECRET = "your_jwt_secret";
const ENCRYPTION_KEY = crypto.randomBytes(32); // Must be 32 bytes for AES-256
const IV = crypto.randomBytes(16); // Initialization vector

// Encrypt function
const encrypt = (payload) => {
  // Create a JWT token from the payload
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

  // Encrypt the JWT token
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, "utf8", "hex");
  encrypted += cipher.final("hex");

  // Return the encrypted token along with IV (encoded)
  return `${IV.toString("hex")}:${encrypted}`;
};

// Decrypt function
const decrypt = (encryptedToken) => {
  const [ivHex, encrypted] = encryptedToken.split(":");
  const iv = Buffer.from(ivHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");

  // Verify the decrypted JWT token
  const decoded = jwt.verify(decrypted, JWT_SECRET);
  return decoded;
};

module.exports = {
  encrypt,
  decrypt,
};
