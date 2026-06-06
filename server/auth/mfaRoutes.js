const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const admin = require('firebase-admin');
const { authenticateToken } = require('../middleware/authMiddleware');
const { generateTokens, setCookieTokens } = require('../sessions/sessionManager');

async function getUserAndDoc(email) {
    const db = admin.firestore();
    const query = await db.collection('users').where('email', '==', email).limit(1).get();
    if (query.empty) return { user: null, docId: null, db };
    return { user: query.docs[0].data(), docId: query.docs[0].id, db };
}

// 1. Setup MFA: Generate secret and QR code
router.post('/setup', authenticateToken, async (req, res) => {
    try {
        const { user, docId, db } = await getUserAndDoc(req.user.email);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const secret = speakeasy.generateSecret({
            name: `RiserGPT (${user.email})`,
            issuer: 'RiserGPT'
        });

        // Temporarily store secret in user object (not yet enabled)
        user.tempMfaSecret = secret.base32;
        await db.collection('users').doc(docId).set(user);

        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
        res.json({ secret: secret.base32, qrCode: qrCodeUrl });
    } catch (e) {
        res.status(500).json({ error: 'Failed to setup MFA' });
    }
});

// 2. Verify MFA: Enable it permanently
router.post('/verify', authenticateToken, async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });

    try {
        const { user, docId, db } = await getUserAndDoc(req.user.email);
        if (!user || !user.tempMfaSecret) return res.status(400).json({ error: 'MFA setup not initiated' });

        const verified = speakeasy.totp.verify({
            secret: user.tempMfaSecret,
            encoding: 'base32',
            token: token
        });

        if (verified) {
            user.mfaSecret = user.tempMfaSecret;
            user.mfaEnabled = true;
            user.tempMfaSecret = null;

            // Generate backup codes
            const backupCodes = [];
            for (let i = 0; i < 8; i++) {
                backupCodes.push(Math.random().toString(36).substr(2, 10).toUpperCase());
            }
            user.backupCodes = backupCodes;

            await db.collection('users').doc(docId).set(user);

            // Re-issue a fully verified token
            const tokens = generateTokens(user, true, req.user.sessionId);
            setCookieTokens(res, tokens.accessToken, tokens.refreshToken);

            res.json({ success: true, backupCodes, token: tokens.accessToken });
        } else {
            res.status(400).json({ error: 'Invalid verification code' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

// 3. Disable MFA
router.post('/disable', authenticateToken, async (req, res) => {
    const { token } = req.body;
    try {
        const { user, docId, db } = await getUserAndDoc(req.user.email);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: token
        });

        if (verified) {
            user.mfaEnabled = false;
            user.mfaSecret = null;
            user.backupCodes = [];
            await db.collection('users').doc(docId).set(user);
            
            // Re-issue token
            const tokens = generateTokens(user, false, req.user.sessionId);
            setCookieTokens(res, tokens.accessToken, tokens.refreshToken);

            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Invalid verification code' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Failed to disable MFA' });
    }
});

// 4. Challenge: Verify MFA during login
router.post('/challenge', authenticateToken, async (req, res) => {
    const { token } = req.body;
    try {
        const { user } = await getUserAndDoc(req.user.email);
        if (!user || !user.mfaEnabled) return res.status(400).json({ error: 'MFA not enabled' });

        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: token
        });

        if (verified) {
            const tokens = generateTokens(user, true, req.user.sessionId);
            setCookieTokens(res, tokens.accessToken, tokens.refreshToken);
            res.json({ success: true, token: tokens.accessToken });
        } else {
            res.status(400).json({ error: 'Invalid verification code' });
        }
    } catch (e) {
        res.status(500).json({ error: 'MFA challenge failed' });
    }
});

// 5. Recovery: Use backup code
router.post('/verify-recovery', authenticateToken, async (req, res) => {
    const { code } = req.body;
    try {
        const { user, docId, db } = await getUserAndDoc(req.user.email);
        if (!user || !user.backupCodes) return res.status(400).json({ error: 'Recovery codes not available' });

        const codeIndex = user.backupCodes.indexOf(code.toUpperCase());
        if (codeIndex > -1) {
            // Remove the used code
            user.backupCodes.splice(codeIndex, 1);
            await db.collection('users').doc(docId).set(user);

            const tokens = generateTokens(user, true, req.user.sessionId);
            setCookieTokens(res, tokens.accessToken, tokens.refreshToken);
            res.json({ success: true, token: tokens.accessToken });
        } else {
            res.status(400).json({ error: 'Invalid recovery code' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Recovery failed' });
    }
});

router.post('/regenerate-recovery', authenticateToken, async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'MFA token required' });

    try {
        const { user, docId, db } = await getUserAndDoc(req.user.email);
        if (!user || !user.mfaSecret) return res.status(400).json({ error: 'MFA not enabled' });

        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: token
        });

        if (verified) {
            const backupCodes = [];
            for (let i = 0; i < 8; i++) {
                backupCodes.push(Math.random().toString(36).substr(2, 10).toUpperCase());
            }
            user.backupCodes = backupCodes;

            await db.collection('users').doc(docId).set(user);
            res.json({ success: true, backupCodes });
        } else {
            res.status(400).json({ error: 'Invalid verification code' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Regeneration failed' });
    }
});

module.exports = router;