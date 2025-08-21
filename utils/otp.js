const crypto = require("crypto");

const OTP_LENGTH = 6;

function generateOtp() {
  // 6-digit numeric OTP
  return "" + Math.floor(100000 + Math.random() * 900000);
}

function hashOtp(otp, salt) {
  // Using HMAC-SHA256 with per-OTP salt
  const hmac = crypto.createHmac("sha256", salt);
  hmac.update(otp);
  return hmac.digest("hex");
}

function makeSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function minutesFromNow(mins) {
  return new Date(Date.now() + mins * 60 * 1000);
}

module.exports = {
  OTP_LENGTH,
  generateOtp,
  hashOtp,
  makeSalt,
  minutesFromNow,
};
