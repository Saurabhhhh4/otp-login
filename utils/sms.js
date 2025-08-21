// utils/sms.js
let twilioClient = null;

function getTwilio() {
  if (twilioClient) return twilioClient;
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!sid || !token) {
    console.warn("Twilio not configured; SMS will be skipped.");
    return null;
  }
  // Lazy import to avoid dependency if unused
  const twilio = require("twilio");
  twilioClient = twilio(sid, token);
  return twilioClient;
}

async function sendOtpSms(to, otp) {
  const client = getTwilio();
  if (!client) {
    console.warn("Skipping SMS send (no Twilio configured).");
    return;
  }
  const from = process.env.TWILIO_FROM;
  if (!from) {
    console.warn("TWILIO_FROM not set; SMS will be skipped.");
    return;
  }
  await client.messages.create({
    body: `Your OTP is ${otp}. It expires in ${
      process.env.OTP_EXP_MINUTES || 5
    } minutes.`,
    from,
    to,
  });
}

module.exports = { sendOtpSms };
