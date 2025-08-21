require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const authRoutes = require("./routes/auth");
const auth = require("./middleware/auth");
const User = require("./models/User");

const app = express();

app.use(cors());
app.use(express.json());

// Connect DB
mongoose.set("strictQuery", true);
mongoose
  .connect(process.env.MONGODB_URI, { dbName: "otp_login" })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("Mongo connection error:", err.message);
    process.exit(1);
  });

// Health
app.get("/", (req, res) => res.send("OTP Login API is running"));

// Auth routes
app.use("/auth", authRoutes);

// A protected route to test your JWT
app.get("/me", auth, async (req, res) => {
  const user = await User.findById(req.user.userId).select(
    "-otpHash -otpSalt -otpAttemptCount -otpExpiresAt -blockedUntil -lastOtpSentAt"
  );
  res.json({ user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
