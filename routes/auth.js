const express = require("express");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");

const User = require("../models/User");
const {
  generateOtp,
  hashOtp,
  makeSalt,
  minutesFromNow,
} = require("../utils/otp");

const router = express.Router();

// Basic rate-limit for OTP endpoints (per IP)
const otpLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min window
  max: 10, // 10 requests per minute
  message: { error: "Too many requests, please try later." },
});

// Simple helper: detect identifier type
function parseIdentifier(identifier) {
  if (!identifier) return null;
  if (identifier.includes("@"))
    return { kind: "email", value: identifier.toLowerCase().trim() };
  // Very simple phone normalization; you can improve regex as needed
  const phone = identifier.replace(/\s+/g, "");
  return { kind: "phone", value: phone };
}

/**
 * POST /auth/request-otp
 * body: { "identifier": "email@domain.com" } OR { "identifier": "+919876543210" }
 */
router.post(
  "/request-otp",
  otpLimiter,
  body("identifier")
    .isString()
    .notEmpty()
    .withMessage("identifier is required"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { identifier } = req.body;
    const parsed = parseIdentifier(identifier);
    if (!parsed) return res.status(400).json({ error: "Invalid identifier" });

    const { kind, value } = parsed;

    try {
      // find or create user
      let user = await User.findOne(
        kind === "email" ? { email: value } : { phone: value }
      );

      if (!user) {
        user = await User.create(
          kind === "email" ? { email: value } : { phone: value }
        );
      }

      // Check resend cooldown
      const cooldownSec = Number(process.env.OTP_RESEND_COOLDOWN_SEC || 30);
      if (
        user.lastOtpSentAt &&
        Date.now() - user.lastOtpSentAt.getTime() < cooldownSec * 1000
      ) {
        const waitSec = Math.ceil(
          (cooldownSec * 1000 - (Date.now() - user.lastOtpSentAt.getTime())) /
            1000
        );
        return res
          .status(429)
          .json({
            error: `Please wait ${waitSec}s before requesting a new OTP.`,
          });
      }

      // Check if user is temporarily blocked due to too many failed attempts
      if (user.blockedUntil && user.blockedUntil > new Date()) {
        const left = Math.ceil((user.blockedUntil - new Date()) / 1000);
        return res
          .status(423)
          .json({ error: `Too many attempts. Try again in ${left}s.` });
      }

      const otp = generateOtp();
      const salt = makeSalt();
      const otpHash = hashOtp(otp, salt);
      const expiry = minutesFromNow(Number(process.env.OTP_EXP_MINUTES || 5));

      user.otpHash = otpHash;
      user.otpSalt = salt;
      user.otpExpiresAt = expiry;
      user.otpAttemptCount = 0;
      user.lastOtpSentAt = new Date();
      await user.save();

      // In real app: send via Email/SMS provider here.
      // For learning/testing: return OTP only in development.
      const devOtp = process.env.NODE_ENV !== "production" ? otp : undefined;

      return res.json({
        message: `OTP sent to your ${kind}. It will expire in ${
          process.env.OTP_EXP_MINUTES || 5
        } minutes.`,
        ...(devOtp ? { devOtp } : {}),
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "Something went wrong" });
    }
  }
);

/**
 * POST /auth/verify-otp
 * body: { "identifier": "email@domain.com", "otp": "123456" }
 * success -> returns JWT
 */
router.post(
  "/verify-otp",
  otpLimiter,
  body("identifier").isString().notEmpty(),
  body("otp").isLength({ min: 6, max: 6 }).withMessage("otp must be 6 digits"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array()[0].msg });

    const { identifier, otp } = req.body;
    const parsed = parseIdentifier(identifier);
    if (!parsed) return res.status(400).json({ error: "Invalid identifier" });

    const { kind, value } = parsed;

    try {
      const user = await User.findOne(
        kind === "email" ? { email: value } : { phone: value }
      );
      if (!user)
        return res
          .status(404)
          .json({ error: "User not found. Request OTP first." });

      // Check block window
      if (user.blockedUntil && user.blockedUntil > new Date()) {
        const left = Math.ceil((user.blockedUntil - new Date()) / 1000);
        return res
          .status(423)
          .json({ error: `Too many attempts. Try again in ${left}s.` });
      }

      // Check expiry
      if (
        !user.otpHash ||
        !user.otpSalt ||
        !user.otpExpiresAt ||
        user.otpExpiresAt < new Date()
      ) {
        return res
          .status(400)
          .json({
            error: "OTP expired or not requested. Please request a new OTP.",
          });
      }

      const computed = hashOtp(otp, user.otpSalt);
      const isMatch = cryptoSafeEqual(user.otpHash, computed);

      if (!isMatch) {
        // increase attempt count and maybe block
        user.otpAttemptCount = (user.otpAttemptCount || 0) + 1;

        const maxAttempts = Number(process.env.MAX_OTP_ATTEMPTS || 5);
        if (user.otpAttemptCount >= maxAttempts) {
          // Block for 10 minutes after max attempts
          user.blockedUntil = new Date(Date.now() + 10 * 60 * 1000);
          // Clear current OTP
          user.otpHash = undefined;
          user.otpSalt = undefined;
          user.otpExpiresAt = undefined;
          user.otpAttemptCount = 0;
        }

        await user.save();
        return res.status(400).json({ error: "Invalid OTP" });
      }

      // Success: clear OTP fields
      user.otpHash = undefined;
      user.otpSalt = undefined;
      user.otpExpiresAt = undefined;
      user.otpAttemptCount = 0;
      user.blockedUntil = undefined;

      if (kind === "email") user.isEmailVerified = true;
      if (kind === "phone") user.isPhoneVerified = true;

      await user.save();

      const token = jwt.sign(
        { userId: user._id.toString(), email: user.email, phone: user.phone },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      return res.json({ token });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "Something went wrong" });
    }
  }
);

// constant-time comparison to avoid timing attacks
function cryptoSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = router;
