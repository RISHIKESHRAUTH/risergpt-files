const express = require('express');
const router = express.Router();
const admin = require('firebase-admin');
const { authenticateToken } = require('../middleware/authMiddleware');

router.get('/active', authenticateToken, async (req, res) => {
    try {
        console.log(`[Firestore Read] collection: users, query: email == ${req.user.email}, location: GET /active, auth: ${req.user.email}`);
        const db = admin.firestore();
        const userQuery = await db.collection('users').where('email', '==', req.user.email).limit(1).get();
        if (userQuery.empty) return res.status(404).json({ error: 'User not found' });
        
        const user = userQuery.docs[0].data();
        res.json({ sessions: user.activeSessions || [], currentSessionId: req.user.sessionId });
    } catch (e) {
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

router.post('/revoke', authenticateToken, async (req, res) => {
    const { sessionId } = req.body;
    try {
        const db = admin.firestore();
        const userQuery = await db.collection('users').where('email', '==', req.user.email).limit(1).get();
        if (userQuery.empty) return res.status(404).json({ error: 'User not found' });
        
        const docId = userQuery.docs[0].id;
        const user = userQuery.docs[0].data();
        
        user.activeSessions = (user.activeSessions || []).filter(s => s.id !== sessionId);
        await db.collection('users').doc(docId).update({ activeSessions: user.activeSessions });
        
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed to revoke session' });
    }
});

router.post('/revoke-all', authenticateToken, async (req, res) => {
    try {
        const db = admin.firestore();
        const userQuery = await db.collection('users').where('email', '==', req.user.email).limit(1).get();
        if (userQuery.empty) return res.status(404).json({ error: 'User not found' });
        
        const docId = userQuery.docs[0].id;
        await db.collection('users').doc(docId).update({ activeSessions: [] });
        
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed to revoke sessions' });
    }
});

router.post('/revoke-current', authenticateToken, async (req, res) => {
    try {
        const db = admin.firestore();
        const userQuery = await db.collection('users').where('email', '==', req.user.email).limit(1).get();
        if (userQuery.empty) return res.status(404).json({ error: 'User not found' });
        
        const docId = userQuery.docs[0].id;
        const user = userQuery.docs[0].data();
        
        const currentIp = req.ip;
        const currentUa = req.headers['user-agent'];

        user.activeSessions = (user.activeSessions || []).filter(s => !(s.ip === currentIp && s.ua === currentUa));
        await db.collection('users').doc(docId).update({ activeSessions: user.activeSessions });
        
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Failed to logout' });
    }
});

module.exports = router;