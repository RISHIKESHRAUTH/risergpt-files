const express = require('express');
const router = express.Router();
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');
const { validateEmail } = require('../verification/emailValidator');
const { generateTokens, setCookieTokens, clearCookieTokens } = require('../sessions/sessionManager');

const USERS_FILE = path.join(__dirname, '../../riser_data/users.json');

router.post('/sync', async (req, res) => {
    try {
        const { idToken, provider } = req.body;
        if (!idToken) return res.status(400).json({ error: 'Missing ID Token' });

        // Verify Firebase Token
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const { uid, email, name, picture, email_verified } = decodedToken;

        // Email validation
        const valRes = validateEmail(email);
        if (!valRes.valid) {
            // Unlink or delete user from firebase if invalid? 
            // Better yet, just deny access and we can handle cleanup elsewhere
            return res.status(403).json({ error: valRes.error });
        }

        // Sync with users.json
        let users = [];
        if (fs.existsSync(USERS_FILE)) {
            users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        }

        const existingIndex = users.findIndex(u => u.email === email);
        let syncedUser;

        const timestamp = new Date().toISOString();

        if (existingIndex > -1) {
            // Update existing user
            users[existingIndex] = {
                ...users[existingIndex],
                uid: uid || users[existingIndex].uid,
                name: name || users[existingIndex].name,
                profileImage: picture || users[existingIndex].profileImage,
                verified: email_verified,
                lastLogin: timestamp
            };
            syncedUser = users[existingIndex];
        } else {
            // Create new user in json
            syncedUser = {
                id: Date.now().toString(),
                uid: uid,
                email: email,
                name: name || email.split('@')[0],
                profileImage: picture || null,
                verified: email_verified,
                authProvider: provider || 'google',
                plan: "Muft Plan",
                planStatus: "active",
                planExpiry: "never",
                daysRemaining: "unlimited",
                isBanned: false,
                createdAt: timestamp,
                lastLogin: timestamp
            };
            users.push(syncedUser);
        }

        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

        // Generate JWTs and set cookies
        const { accessToken, refreshToken } = generateTokens(syncedUser);
        setCookieTokens(res, accessToken, refreshToken);

        res.json({ success: true, user: syncedUser, token: accessToken }); // Return token for fallback compatibility
    } catch (error) {
        console.error('Auth Sync Error:', error);
        res.status(401).json({ error: 'Authentication failed. Invalid token.' });
    }
});

router.post('/logout', (req, res) => {
    clearCookieTokens(res);
    res.json({ success: true });
});

module.exports = router;