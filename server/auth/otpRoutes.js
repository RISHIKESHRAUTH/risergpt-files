const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const { 
    sendVerificationEmail, 
    sendVerificationSuccessEmail,
    sendResetPasswordEmail,
    sendResetSuccessEmail 
} = require('../email/emailService');
const rateLimit = require('express-rate-limit');

const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { error: 'Too many OTP requests. Please try again later.' }
});

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function getUserAndDoc(email) {
    const db = admin.firestore();
    const query = await db.collection('users').where('email', '==', email).limit(1).get();
    if (query.empty) return { user: null, docId: null, db };
    return { user: query.docs[0].data(), docId: query.docs[0].id, db };
}

router.post('/send-verification', otpLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required.' });

        const { user, docId, db } = await getUserAndDoc(email);
        if (!user) return res.status(404).json({ error: 'User not found.' });

        if (user.verified) return res.status(400).json({ error: 'Email is already verified.' });

        const now = Date.now();
        if (user.lastVerificationAttempt && (now - user.lastVerificationAttempt) < 60000) {
            return res.status(429).json({ error: 'Please wait 1 minute before requesting another OTP.' });
        }

        const otp = generateOTP();
        user.otpHash = await bcrypt.hash(otp, 10);
        user.otpCreatedAt = now;
        user.lastVerificationAttempt = now;
        user.verificationPending = true;
        await db.collection('users').doc(docId).set(user);

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

        const { user, docId, db } = await getUserAndDoc(email);
        if (!user) return res.status(404).json({ error: 'User not found.' });
        if (user.verified) return res.status(400).json({ error: 'Email is already verified.' });
        if (!user.otpHash || !user.otpCreatedAt) return res.status(400).json({ error: 'No OTP requested.' });

        if (Date.now() - user.otpCreatedAt > 10 * 60 * 1000) {
            return res.status(400).json({ error: 'OTP has expired.' });
        }

        user.otpAttempts = (user.otpAttempts || 0) + 1;
        if (user.otpAttempts > 5) {
            if(!user.securityLogs) user.securityLogs = [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Max OTP attempts reached' });
            user.otpHash = null;
            user.otpCreatedAt = null;
            await db.collection('users').doc(docId).set(user);
            return res.status(400).json({ error: 'Too many incorrect attempts. Please request a new code.' });
        }

        const isValid = await bcrypt.compare(otp.toString(), user.otpHash);
        if (!isValid) {
            if(!user.securityLogs) user.securityLogs = [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Failed OTP attempt' });
            await db.collection('users').doc(docId).set(user);
            return res.status(400).json({ error: 'Invalid OTP.' });
        }

        user.verified = true;
        user.verificationPending = false;
        user.otpHash = null;
        user.otpCreatedAt = null;
        user.lastVerificationAttempt = null;
        user.otpAttempts = null;
        if(!user.securityLogs) user.securityLogs = [];
        user.securityLogs.push({ time: new Date().toISOString(), event: 'Email Verified' });
        await db.collection('users').doc(docId).set(user);

        sendVerificationSuccessEmail(email, user.name).catch(err => console.error(err));

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

        const { user, docId, db } = await getUserAndDoc(email);
        if (!user) {
            return res.json({ success: true, message: 'If the email exists, a reset code has been sent.' });
        }
        
        const now = Date.now();
        if (user.lastVerificationAttempt && (now - user.lastVerificationAttempt) < 60000) {
            return res.status(429).json({ error: 'Please wait 1 minute before requesting another OTP.' });
        }

        const otp = generateOTP();
        user.otpHash = await bcrypt.hash(otp, 10);
        user.otpCreatedAt = now;
        user.lastVerificationAttempt = now;
        user.passwordResetPending = true;
        await db.collection('users').doc(docId).set(user);

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

        const { user, docId, db } = await getUserAndDoc(email);
        if (!user) return res.status(404).json({ error: 'Invalid operation.' });

        if (!user.passwordResetPending || !user.otpHash || !user.otpCreatedAt) {
            return res.status(400).json({ error: 'No reset requested.' });
        }

        if (Date.now() - user.otpCreatedAt > 10 * 60 * 1000) {
            return res.status(400).json({ error: 'OTP has expired.' });
        }

        user.otpAttempts = (user.otpAttempts || 0) + 1;
        if (user.otpAttempts > 5) {
            if(!user.securityLogs) user.securityLogs = [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Max Forgot Pwd OTP attempts reached' });
            user.otpHash = null;
            user.otpCreatedAt = null;
            await db.collection('users').doc(docId).set(user);
            return res.status(400).json({ error: 'Too many incorrect attempts. Please request a new code.' });
        }

        const isValid = await bcrypt.compare(otp.toString(), user.otpHash);
        if (!isValid) {
            if(!user.securityLogs) user.securityLogs = [];
            user.securityLogs.push({ time: new Date().toISOString(), event: 'Failed Password Reset OTP attempt' });
            await db.collection('users').doc(docId).set(user);
            return res.status(400).json({ error: 'Invalid OTP.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.passwordResetPending = false;
        user.otpHash = null;
        user.otpCreatedAt = null;
        user.lastVerificationAttempt = null;
        user.otpAttempts = null;
        if(!user.securityLogs) user.securityLogs = [];
        user.securityLogs.push({ time: new Date().toISOString(), event: 'Password Reset Successful' });
        await db.collection('users').doc(docId).set(user);

        sendResetSuccessEmail(email).catch(err => console.error(err));

        res.json({ success: true, message: 'Password reset successfully.' });
    } catch (error) {
        console.error('Reset password error', error);
        res.status(500).json({ error: 'Service temporarily unavailable.' });
    }
});

module.exports = router;