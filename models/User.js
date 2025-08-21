const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      trim: true,
      lowercase: true,
      index: true,
      sparse: true,
      unique: true,
    },
    phone: {
      type: String,
      trim: true,
      index: true,
      sparse: true,
      unique: true,
    },
    // OTP fields (hashed)
    otpHash: String,
    otpSalt: String,
    otpExpiresAt: Date,
    otpAttemptCount: { type: Number, default: 0 },
    blockedUntil: Date,
    lastOtpSentAt: Date,

    // Optional flags
    isEmailVerified: { type: Boolean, default: false },
    isPhoneVerified: { type: Boolean, default: false },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
