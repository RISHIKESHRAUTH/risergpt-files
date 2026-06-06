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
 * Premium Dark, High-Trust HTML template with RiserGPT branding.
 */
const premiumTemplate = (bodyContent, title = 'Security Notification', preheader = '') => `
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="x-apple-disable-message-reformatting">
    <title>RiserGPT</title>
    <!--[if mso]>
    <style type="text/css">
      table, td {font-family: Arial, Helvetica, sans-serif;}
    </style>
    <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #0c0c0e; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #ffffff; -webkit-font-smoothing: antialiased;">
    <!-- Preheader Text -->
    <div style="display: none; max-height: 0px; overflow: hidden; font-size: 0px; line-height: 0px; color: #0c0c0e;">
        ${preheader || title} &zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;
    </div>
    
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed; background-color: #0c0c0e;">
        <tr>
            <td align="center" style="padding: 40px 15px;">
                <!-- Main Container -->
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #141417; border: 1px solid #27272a; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="background: linear-gradient(135deg, #1e293b 0%, #0c0c0e 100%); padding: 40px 20px; border-bottom: 1px solid #27272a;">
                            <table border="0" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center">
                                        <div style="width: 48px; height: 48px; border-radius: 12px; background: linear-gradient(135deg, #2563eb, #1d4ed8); display: inline-block; box-shadow: 0 0 20px rgba(59, 130, 246, 0.5); text-align: center; line-height: 48px; font-family: -apple-system, system-ui, sans-serif; font-size: 24px; font-weight: bold; color: #ffffff; margin-bottom: 16px;">
                                            <span style="font-family: inherit;">R</span>
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <td align="center">
                                        <h1 style="margin: 0; font-size: 28px; font-weight: 800; letter-spacing: -0.05em; color: #ffffff; text-transform: uppercase;">RISER<span style="color: #3b82f6;">GPT</span></h1>
                                    </td>
                                </tr>
                                <tr>
                                    <td align="center">
                                        <p style="margin: 10px 0 0 0; color: #94a3b8; font-size: 14px; text-transform: uppercase; letter-spacing: 2px;">Securing your Intelligence</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px; color: #d1d5db; font-size: 16px; line-height: 1.6;">
                            <h2 style="margin: 0 0 20px 0; color: #ffffff; font-size: 22px; font-weight: 700;">${title}</h2>
                            ${bodyContent}
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="background-color: #0c0c0e; padding: 30px; font-size: 13px; color: #71717a; border-top: 1px solid #27272a;">
                            <p style="margin: 0 0 10px 0;">This is an automated security message from RiserGPT AI Platform.</p>
                            <p style="margin: 0;">&copy; ${new Date().getFullYear()} RiserGPT &middot; <a href="https://risergpt.qzz.io" style="color: #3b82f6; text-decoration: none;">Visit Platform</a></p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
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
    const subject = `${otp} is your RiserGPT verification code`;
    const preheader = `Your verification code is ${otp}. Use this to complete your sign in.`;
    const bodyContent = `
        <p style="margin: 0 0 16px 0;">Welcome to RiserGPT. To complete your registration and secure your account, please use the following one-time password (OTP):</p>
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 12px; padding: 30px; text-align: center; margin: 30px 0;">
            <p style="font-family: 'Courier New', Courier, monospace; font-size: 42px; font-weight: 800; letter-spacing: 8px; color: #3b82f6; margin: 0; text-shadow: 0 0 20px rgba(59, 130, 246, 0.3);">${otp}</p>
        </div>
        <p style="margin: 0 0 16px 0;">This code is valid for <strong>10 minutes</strong>. If you did not request this code, your account may be at risk. Please ignore this email or contact support if you have concerns.</p>
        <div style="font-size: 14px; color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; margin-top: 20px;">
            <strong>Security Note:</strong> RiserGPT staff will never ask for your OTP or password over email or phone.
        </div>
    `;
    const text = `Your RiserGPT verification code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nSecuring your Intelligence - RiserGPT`;
    
    return sendEmail({ to, subject, html: premiumTemplate(bodyContent, 'Verify your email', preheader), text });
}

/**
 * Password Reset OTP Email
 */
async function sendResetPasswordEmail(to, otp) {
    const subject = `${otp} is your RiserGPT password reset code`;
    const preheader = `Your password reset code is ${otp}.`;
    const bodyContent = `
        <p style="margin: 0 0 16px 0;">A password reset was requested for your RiserGPT account. Use the code below to proceed with the reset process:</p>
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 12px; padding: 30px; text-align: center; margin: 30px 0;">
            <p style="font-family: 'Courier New', Courier, monospace; font-size: 42px; font-weight: 800; letter-spacing: 8px; color: #3b82f6; margin: 0; text-shadow: 0 0 20px rgba(59, 130, 246, 0.3);">${otp}</p>
        </div>
        <p style="margin: 0 0 16px 0;">This code is valid for <strong>10 minutes</strong>. If you did not request this, no action is required and your password remains unchanged.</p>
        <div style="font-size: 14px; color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; margin-top: 20px;">
            If you did not initiate this request, we recommend reviewing your account security settings.
        </div>
    `;
    const text = `Your RiserGPT password reset code is: ${otp}\n\nThis code is valid for 10 minutes.\n\nSecuring your Intelligence - RiserGPT`;

    return sendEmail({ to, subject, html: premiumTemplate(bodyContent, 'Password Reset Request', preheader), text });
}

/**
 * Security Alert: New Login detected
 */
async function sendLoginAlertEmail(to, name, deviceInfo = 'unknown device') {
    const subject = 'Security Alert: New Login to RiserGPT';
    const preheader = `A new login was detected on your account from ${deviceInfo}.`;
    const timestamp = new Date().toUTCString();
    const bodyContent = `
        <p style="margin: 0 0 16px 0;">A new login was detected on your RiserGPT account.</p>
        <div style="background-color: rgba(255, 255, 255, 0.05); padding: 16px; border: 1px solid #27272a; border-radius: 6px; margin: 20px 0;">
            <p style="margin: 0 0 8px 0; font-size: 14px; color: #ffffff;"><strong>Time:</strong> <span style="color: #94a3b8;">${timestamp}</span></p>
            <p style="margin: 0; font-size: 14px; color: #ffffff;"><strong>Device:</strong> <span style="color: #94a3b8;">${deviceInfo}</span></p>
        </div>
        <p style="margin: 0 0 16px 0;">If this was you, you can ignore this alert. If you do not recognize this login, please reset your password immediately to secure your account.</p>
    `;
    const text = `Security alert: New login was detected on your RiserGPT account.\n\nTime: ${timestamp}\nDevice: ${deviceInfo}\n\nIf this was not you, please secure your account immediately.\n\nRiserGPT AI Platform`;

    return sendEmail({ to, subject, html: premiumTemplate(bodyContent, 'New Login Detected', preheader), text });
}

/**
 * Account Verification Success
 */
async function sendVerificationSuccessEmail(to, name) {
    const subject = 'Welcome to RiserGPT - Account Verified';
    const preheader = `Your account has been successfully verified. Welcome to RiserGPT.`;
    const bodyContent = `
        <p style="margin: 0 0 16px 0;">Congratulations! Your RiserGPT account has been successfully verified.</p>
        <p style="margin: 0 0 16px 0;">You now have full access to our neural intelligence engines, including RH-6 and professional search tools.</p>
        <p style="margin-top: 30px; text-align: center;">
            <a href="https://risergpt.qzz.io" style="background-color: #3b82f6; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; display: inline-block;">Launch Dashboard</a>
        </p>
    `;
    const text = `Your RiserGPT account has been successfully verified. Welcome to the future of intelligence.\n\nRiserGPT AI Platform`;

    return sendEmail({ to, subject, html: premiumTemplate(bodyContent, 'Account Verified', preheader), text });
}

/**
 * Password Reset Success Confirmation
 */
async function sendResetSuccessEmail(to) {
    const subject = 'Security Update: Password Changed';
    const preheader = `Your RiserGPT password was successfully changed.`;
    const bodyContent = `
        <p style="margin: 0 0 16px 0;">This is a confirmation that the password for your RiserGPT account was recently changed.</p>
        <p style="margin: 0 0 16px 0;">If you made this change, you can ignore this email. No further action is required.</p>
        <div style="font-size: 14px; color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; margin-top: 20px;">
            <strong>If you did NOT change your password:</strong> Please contact our security team immediately at <a href="mailto:official@risergpt.qzz.io" style="color: #3b82f6; text-decoration: underline;">official@risergpt.qzz.io</a> to freeze your account.
        </div>
    `;
    const text = `Your RiserGPT password has been successfully reset.\n\nRiserGPT AI Platform`;

    return sendEmail({ to, subject, html: premiumTemplate(bodyContent, 'Password Changed Successfully', preheader), text });
}

module.exports = {
    sendVerificationEmail,
    sendVerificationSuccessEmail,
    sendResetPasswordEmail,
    sendResetSuccessEmail,
    sendLoginAlertEmail
};