const express = require('express');
const router = express.Router();
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const { validateEmail } = require('../verification/emailValidator');
const { generateTokens, setCookieTokens, clearCookieTokens } = require('../sessions/sessionManager');
const { authenticateToken } = require('../middleware/authMiddleware');

async function getUserAndDoc(email, context = "Unknown") {
    console.log(`[Firestore Read] collection: users, query: email == ${email}, location: ${context}, auth: ${email}`);
    const db = admin.firestore();
    const query = await db.collection('users').where('email', '==', email).limit(1).get();
    if (query.empty) return { user: null, docId: null, db };
    return { user: query.docs[0].data(), docId: query.docs[0].id, db };
}

router.post('/sync', async (req, res) => {
    try {
        const { idToken, provider } = req.body;
        if (!idToken) return res.status(400).json({ error: 'Missing ID Token' });

        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const { uid, email, name, picture, email_verified } = decodedToken;

        const valRes = validateEmail(email);
        if (!valRes.valid) return res.status(403).json({ error: valRes.error });

        let { user, docId, db } = await getUserAndDoc(email);

        if (user) {
            user.lastLogin = new Date().toISOString();
        } else {
            user = {
                uid: uid,
                email: email,
                password: await bcrypt.hash(Date.now().toString() + Math.random(), 10),
                name: name || email.split('@')[0],
                photoURL: picture || null,
                verified: true,
                provider: 'google',
                lastLogin: new Date().toISOString(),
                role: 'user',
                status: 'active',
                createdAt: new Date().toISOString(),
                isBanned: false,
                plan: "Muft Plan",
                planStatus: "active",
                planExpiry: "never",
                daysRemaining: "unlimited",
                securityLogs: [],
                trustedDevices: [],
                mfaEnabled: false,
                activeSessions: []
            };
            docId = db.collection('users').doc(uid).id;
        }

        const session = {
            id: Date.now().toString(),
            ua: req.headers['user-agent'],
            ip: req.ip,
            lastSeen: new Date().toISOString()
        };
        if(!user.activeSessions) user.activeSessions = [];
        user.activeSessions.push(session);
        if (user.activeSessions.length > 5) user.activeSessions.shift();

        await db.collection('users').doc(docId).set(user, { merge: true });

        const mfaRequired = user.mfaEnabled === true;
        const { accessToken, refreshToken } = generateTokens(user, !mfaRequired, session.id);
        setCookieTokens(res, accessToken, refreshToken);

        const userForClient = { ...user, id: docId };
        delete userForClient.password;
        delete userForClient.mfaSecret;
        delete userForClient.backupCodes;
        delete userForClient.tempMfaSecret;

        res.json({ 
            success: true, 
            user: userForClient, 
            token: accessToken,
            requiresMfa: mfaRequired
        });
    } catch (error) {
        console.error('Auth Sync Error:', error);
        res.status(401).json({ error: 'Authentication failed. Invalid token.' });
    }
});

router.post('/logout', (req, res) => {
    clearCookieTokens(res);
    res.json({ success: true });
});

router.post('/profile/update', authenticateToken, async (req, res) => {
    try {
        const { name, photoURL } = req.body;
        if (!name) return res.status(400).json({ error: 'Name is required' });

        const { user, docId, db } = await getUserAndDoc(req.user.email);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const updates = { name: name };
        user.name = name;
        
        if (photoURL !== undefined) {
            updates.photoURL = photoURL;
            user.photoURL = photoURL;
        }

        await db.collection('users').doc(docId).update(updates);

        res.json({ success: true, name: user.name, photoURL: user.photoURL });
    } catch (error) {
        res.status(500).json({ error: 'Update failed' });
    }
});

router.post('/profile/password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'All fields are required' });

        const { user, docId, db } = await getUserAndDoc(req.user.email);
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (user.authProvider === 'google' && (!user.password || user.password.length < 20)) {
            return res.status(403).json({ error: 'Please use Forgot Password for Google accounts.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Current password incorrect' });

        user.password = await bcrypt.hash(newPassword, 10);
        await db.collection('users').doc(docId).update({ password: user.password });

        res.json({ success: true, message: 'Password updated' });
    } catch (error) {
        res.status(500).json({ error: 'Update failed' });
    }
});

module.exports = router;