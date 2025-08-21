// utils/mailer.js
const nodemailer = require("nodemailer");

let transporter;

function getTransporter() {
  if (transporter) return transporter;

  if (!process.env.SMTP_HOST) {
    console.warn("SMTP not configured; emails will be skipped.");
    return null;
  }

  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false, // use TLS with port 465; otherwise false
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  return transporter;
}

async function sendOtpEmail(to, otp) {
  const tx = getTransporter();
  if (!tx) {
    console.warn("Skipping email send (no SMTP configured).");
    return;
  }

  const from = process.env.SMTP_FROM || "no-reply@example.com";
  const subject = "Your OTP Code";
  const text = `Your OTP is ${otp}. It expires in ${
    process.env.OTP_EXP_MINUTES || 5
  } minutes.`;
  const html = `
    <div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:520px">
      <h2 style="margin:0 0 12px">OTP Verification</h2>
      <p style="margin:0 0 16px">Use the code below to continue. It will expire in <b>${
        process.env.OTP_EXP_MINUTES || 5
      } minutes</b>.</p>
      <div style="font-size:28px;letter-spacing:4px;font-weight:700;padding:12px 16px;border:1px solid #ddd;border-radius:10px;display:inline-block;">
        ${otp}
      </div>
      <p style="margin:16px 0 0;color:#666;font-size:12px">If you didn’t request this, you can ignore this email.</p>
    </div>
  `;

  await tx.sendMail({ from, to, subject, text, html });
}

module.exports = { sendOtpEmail };
