/**
 * RiserGPT Email Service
 * Production-grade, Gmail-optimized delivery using Resend.
 * Designed to maximize deliverability and comply with transactional trust signals.
 */

const { Resend } = require('resend');

// Initialize Resend with API Key
const resend = new Resend(process.env.RESEND_API_KEY);

// Standard Delivery Headers (Optimized for Transactional Trust)
const EMAIL_FROM = 'RiserGPT <official@risergpt.qzz.io>';
const REPLY_TO = 'official@risergpt.qzz.io';

/**
 * Ultra-Minimal, High-Trust HTML template.
 * Uses system fonts and avoids all spam triggers (no big colors, no buttons, no emojis).
 */
const minimalTemplate = (bodyContent) => `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #111111; line-height: 1.6; margin: 0; padding: 0; }
        .wrapper { max-width: 580px; margin: 40px auto; padding: 20px; }
        .content { font-size: 16px; margin-bottom: 30px; }
        .otp-display { background-color: #f7f9fc; border: 1px solid #e1e4e8; border-radius: 6px; padding: 24px; text-align: center; margin: 24px 0; }
        .otp-code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #111111; margin: 0; }
        .footer { border-top: 1px solid #eeeeee; padding-top: 20px; font-size: 12px; color: #666666; text-align: left; }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="content">
            ${bodyContent}
        </div>
        <div class="footer">
            <p style="margin: 0 0 5px 0;"><strong>RiserGPT AI Platform</strong></p>
            <p style="margin: 0;">This is a transactional message sent to verify your identity. If you have questions, please contact official@risergpt.qzz.io.</p>
        </div>
    </div>
</body>
</html>
`;

/**
 * Core email dispatcher with Anti-Spam Headers
 */
async function sendEmail({ to, subject, html, text }) {
    try {
        if (!process.env.RESEND_API_KEY) {
            console.error('[EmailService] RESEND_API_KEY is missing.');
            return false;
        }

        const { data, error } = await resend.emails.send({
            from: EMAIL_FROM,
            to: [to],
            replyTo: REPLY_TO,
            subject: subject,
            html: html,
            text: text, // Essential plain-text fallback
            headers: {
                'X-Entity-Ref-ID': Date.now().toString(),
                'Precedence': 'bulk',
                'X-Auto-Response-Suppress': 'All'
            }
        });

        if (error) {
            console.error('[EmailService] Send Error:', error);
            return false;
        }

        return true;
    } catch (err) {
        console.error('[EmailService] Exception:', err);
        return false;
    }
}

/**
 * OTP Verification Email
 */
async function sendVerificationEmail(to, otp) {
    const subject = 'Your RiserGPT verification code';
    const bodyContent = `
        <p>Your verification code is below. Please enter this code in the RiserGPT app to verify your email address.</p>
        <div class="otp-display">
            <p class="otp-code">${otp}</p>
        </div>
        <p>This code is valid for 10 minutes. If you did not request this, you can safely ignore this email.</p>
    `;
    const text = `Your RiserGPT verification code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nRiserGPT AI Platform`;
    
    return sendEmail({ to, subject, html: minimalTemplate(bodyContent), text });
}

/**
 * Password Reset OTP Email
 */
async function sendResetPasswordEmail(to, otp) {
    const subject = 'Your password reset code';
    const bodyContent = `
        <p>You requested a password reset for your RiserGPT account. Use the following code to continue:</p>
        <div class="otp-display">
            <p class="otp-code">${otp}</p>
        </div>
        <p>This code is valid for 10 minutes. If you did not request a password reset, no action is needed.</p>
    `;
    const text = `Your RiserGPT password reset code is: ${otp}\n\nThis code is valid for 10 minutes.\n\nRiserGPT AI Platform`;

    return sendEmail({ to, subject, html: minimalTemplate(bodyContent), text });
}

/**
 * Security Alert: New Login detected
 */
async function sendLoginAlertEmail(to, name, deviceInfo = 'unknown device') {
    const subject = 'Security alert: New login detected';
    const timestamp = new Date().toUTCString();
    const bodyContent = `
        <p>A new login was detected on your RiserGPT account.</p>
        <div style="background-color: #f7f9fc; padding: 16px; border: 1px solid #e1e4e8; border-radius: 6px; margin: 20px 0;">
            <p style="margin: 0 0 8px 0; font-size: 14px;"><strong>Time:</strong> ${timestamp}</p>
            <p style="margin: 0; font-size: 14px;"><strong>Device:</strong> ${deviceInfo}</p>
        </div>
        <p>If this was you, you can ignore this alert. If you do not recognize this login, please reset your password immediately to secure your account.</p>
    `;
    const text = `Security alert: New login was detected on your RiserGPT account.\n\nTime: ${timestamp}\nDevice: ${deviceInfo}\n\nIf this was not you, please secure your account immediately.\n\nRiserGPT AI Platform`;

    return sendEmail({ to, subject, html: minimalTemplate(bodyContent), text });
}

/**
 * Account Verification Success
 */
async function sendVerificationSuccessEmail(to, name) {
    const subject = 'Account verified successfully';
    const bodyContent = `
        <p>Your RiserGPT account has been successfully verified. You can now use all platform features.</p>
    `;
    const text = `Your RiserGPT account has been successfully verified.\n\nRiserGPT AI Platform`;

    return sendEmail({ to, subject, html: minimalTemplate(bodyContent), text });
}

/**
 * Password Reset Success Confirmation
 */
async function sendResetSuccessEmail(to) {
    const subject = 'Password reset successful';
    const bodyContent = `
        <p>The password for your RiserGPT account has been successfully reset.</p>
        <p>If you did not perform this change, please contact us immediately at official@risergpt.qzz.io.</p>
    `;
    const text = `Your RiserGPT password has been successfully reset.\n\nRiserGPT AI Platform`;

    return sendEmail({ to, subject, html: minimalTemplate(bodyContent), text });
}

module.exports = {
    sendVerificationEmail,
    sendVerificationSuccessEmail,
    sendResetPasswordEmail,
    sendResetSuccessEmail,
    sendLoginAlertEmail
};