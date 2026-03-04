import nodemailer from "nodemailer";
import {
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
} from "$env/static/private";

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: false,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

export async function sendVerificationEmail(
  email: string,
  token: string,
  origin: string
) {
  const url = `${origin}/verify-email?token=${token}`;

  await transporter.sendMail({
    from: `"AuthApp" <${SMTP_USER}>`,
    to: email,
    subject: "Verify your email - AuthApp",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
        <h2 style="color: #1f2937;">Verify your email</h2>
        <p style="color: #4b5563;">Click the button below to verify your email address:</p>
        <a href="${url}" style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 16px 0;">
          Verify Email
        </a>
        <p style="color: #9ca3af; font-size: 14px;">This link expires in 24 hours.</p>
        <p style="color: #9ca3af; font-size: 14px;">If you didn't create an account, you can ignore this email.</p>
      </div>
    `,
  });
}

export async function sendPasswordResetEmail(
  email: string,
  token: string,
  origin: string
) {
  const url = `${origin}/reset-password?token=${token}`;

  await transporter.sendMail({
    from: `"AuthApp" <${SMTP_USER}>`,
    to: email,
    subject: "Reset your password - AuthApp",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
        <h2 style="color: #1f2937;">Reset your password</h2>
        <p style="color: #4b5563;">Click the button below to reset your password:</p>
        <a href="${url}" style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 16px 0;">
          Reset Password
        </a>
        <p style="color: #9ca3af; font-size: 14px;">This link expires in 1 hour.</p>
        <p style="color: #9ca3af; font-size: 14px;">If you didn't request this, you can ignore this email.</p>
      </div>
    `,
  });
}
