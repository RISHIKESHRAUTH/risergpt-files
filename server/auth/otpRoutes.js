const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { 
    sendVerificationEmail, 
    sendVerificationSuccessEmail,
    sendResetPasswordEmail,
    sendResetSuccessEmail 
} = require('../email/emailService');
const { validateEmail } = require('../verification/emailValidator');
const rateLimit = require('express-rate-limit');
const { USERS_FILE } = require('../config/paths');

const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 mins
    max: 5, // max 5 requests per IP
    message: { error: 'Too many OTP requests. Please try again later.' }
});

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function readUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

router.post('/send-verification', otpLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required.' });

        const users = readUsers();
        const userIndex = users.findIndex(u => u.email === email);
        if (userIndex === -1) return res.status(404).json({ error: 'User not found.' });

        const user = users[userIndex];
        if (user.verified) return res.status(400).json({ error: 'Email is already verified.' });

        // Add cooldown check
        const now = Date.now();
        if (user.lastVerificationAttempt && (now - user.lastVerificationAttempt) < 60000) {
            return res.status(429).json({ error: 'Please wait 1 minute before requesting another OTP.' });
        }

        const otp = generateOTP();
        const hashedOtp = await bcrypt.hash(otp, 10);

        user.otpHash = hashedOtp;
        user.otpCreatedAt = now;
        user.lastVerificationAttempt = now;
        user.verificationPending = true;

        writeUsers(users);

        const emailSent = await sendVerificationEmail(email, otp);
        if (!emailSent) {
            return res.status(500).json({ error: 'Failed to send verification email. Please try again later.' });
        }

        res.json({ success: true, message: 'Verification email sent.' });

    } catch (error) {
        console.error('Send OTP error', error);
        res.status(500).json({ error: 'Service temporarily unavailable.' });
    }
});

router.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required.' });

        const users = readUsers();
        const userIndex = users.findIndex(u => u.email === email);
        if (userIndex === -1) return res.status(404).json({ error: 'User not found.' });

        const user = users[userIndex];
        if (user.verified) return res.status(400).json({ error: 'Email is already verified.' });
        if (!user.otpHash || !user.otpCreatedAt) return res.status(400).json({ error: 'No OTP requested.' });

        // Ensure OTP has not expired (10 minutes)
        if (Date.now() - user.otpCreatedAt > 10 * 60 * 1000) {
            return res.status(400).json({ error: 'OTP has expired.' });
        }

        user.otpAttempts = (user.otpAttempts || 0) + 1;
        if (user.otpAttempts > 5) {
            user.securityLogs = user.securityLogs || [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Max OTP attempts reached' });
            // Require them to send a new OTP
            delete user.otpHash;
            delete user.otpCreatedAt;
            writeUsers(users);
            return res.status(400).json({ error: 'Too many incorrect attempts. Please request a new code.' });
        }

        const isValid = await bcrypt.compare(otp.toString(), user.otpHash);
        if (!isValid) {
            user.securityLogs = user.securityLogs || [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Failed OTP attempt' });
            writeUsers(users);
            return res.status(400).json({ error: 'Invalid OTP.' });
        }

        user.verified = true;
        user.verificationPending = false;
        const userName = user.name;
        delete user.otpHash;
        delete user.otpCreatedAt;
        delete user.lastVerificationAttempt;
        delete user.otpAttempts;
        user.securityLogs = user.securityLogs || [];
        user.securityLogs.push({ time: new Date().toISOString(), event: 'Email Verified' });

        writeUsers(users);

        // Send success email asynchronously
        sendVerificationSuccessEmail(email, userName).catch(err => console.error('Error sending verification success email', err));

        res.json({ success: true, message: 'Email verified successfully.' });
    } catch (error) {
        console.error('Verify OTP error', error);
        res.status(500).json({ error: 'Service temporarily unavailable.' });
    }
});

router.post('/forgot-password', otpLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required.' });

        const users = readUsers();
        const userIndex = users.findIndex(u => u.email === email);
        if (userIndex === -1) {
            // Silently return success to prevent email enumeration
            return res.json({ success: true, message: 'If the email exists, a reset code has been sent.' });
        }

        const user = users[userIndex];
        
        const now = Date.now();
        if (user.lastVerificationAttempt && (now - user.lastVerificationAttempt) < 60000) {
            return res.status(429).json({ error: 'Please wait 1 minute before requesting another OTP.' });
        }

        const otp = generateOTP();
        const hashedOtp = await bcrypt.hash(otp, 10);

        user.otpHash = hashedOtp;
        user.otpCreatedAt = now;
        user.lastVerificationAttempt = now;
        user.passwordResetPending = true;

        writeUsers(users);

        await sendResetPasswordEmail(email, otp);

        res.json({ success: true, message: 'If the email exists, a reset code has been sent.' });

    } catch (error) {
        console.error('Forgot password error', error);
        res.status(500).json({ error: 'Service temporarily unavailable.' });
    }
});

router.post('/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        if (!email || !otp || !newPassword) return res.status(400).json({ error: 'Email, OTP, and new password are required.' });

        if (newPassword.length < 6 || newPassword.length > 100) {
            return res.status(400).json({ error: 'Password must be between 6 and 100 characters.' });
        }

        const users = readUsers();
        const userIndex = users.findIndex(u => u.email === email);
        if (userIndex === -1) return res.status(404).json({ error: 'Invalid operation.' });

        const user = users[userIndex];
        if (!user.passwordResetPending || !user.otpHash || !user.otpCreatedAt) {
            return res.status(400).json({ error: 'No reset requested.' });
        }

        if (Date.now() - user.otpCreatedAt > 10 * 60 * 1000) {
            return res.status(400).json({ error: 'OTP has expired.' });
        }

        user.otpAttempts = (user.otpAttempts || 0) + 1;
        if (user.otpAttempts > 5) {
            user.securityLogs = user.securityLogs || [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Max Forgot Pwd OTP attempts reached' });
            delete user.otpHash;
            delete user.otpCreatedAt;
            writeUsers(users);
            return res.status(400).json({ error: 'Too many incorrect attempts. Please request a new code.' });
        }

        const isValid = await bcrypt.compare(otp.toString(), user.otpHash);
        if (!isValid) {
            user.securityLogs = user.securityLogs || [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Failed Password Reset OTP attempt' });
            writeUsers(users);
            return res.status(400).json({ error: 'Invalid OTP.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.passwordResetPending = false;
        delete user.otpHash;
        delete user.otpCreatedAt;
        delete user.lastVerificationAttempt;
        delete user.otpAttempts;
        user.securityLogs = user.securityLogs || [];
        user.securityLogs.push({ time: new Date().toISOString(), event: 'Password Reset Successful' });

        writeUsers(users);

        // Send success email asynchronously
        sendResetSuccessEmail(email).catch(err => console.error('Error sending reset success email', err));

        res.json({ success: true, message: 'Password reset successfully.' });

    } catch (error) {
        console.error('Reset password error', error);
        res.status(500).json({ error: 'Service temporarily unavailable.' });
    }
});

module.exports = router;