const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../sessions/sessionManager');
const admin = require('firebase-admin');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        token = req.cookies.accessToken;
    }
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    jwt.verify(token, JWT_SECRET, async (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        
        if (user && user.role === 'admin') {
            req.user = user;
            return next();
        }
        
        // Load full user from database to check mfa status
        try {
            console.log(`[Firestore Read] collection: users, query: email == ${user.email}, location: Auth Middleware, auth: middleware jwt`);
            const db = admin.firestore();
            const userQuery = await db.collection('users').where('email', '==', user.email).limit(1).get();
            const dbUser = userQuery.empty ? null : userQuery.docs[0].data();
            
            if (dbUser) {
                // Ban check mechanism
                if (dbUser.isBanned) {
                    if (dbUser.activeSessions && dbUser.activeSessions.length > 0) {
                        await db.collection('users').doc(userQuery.docs[0].id).update({ activeSessions: [] });
                    }
                    return res.status(403).json({ error: 'Your account has been suspended', isBanned: true });
                }

                // MFA sensitive routes check
                if (dbUser.mfaEnabled && !user.mfaVerified) {
                    const sensitiveRoutes = [
                        '/api/auth/profile/password',
                        '/api/auth/mfa/disable',
                        '/api/auth/mfa/regenerate-recovery'
                    ];
                    let isSensitive = sensitiveRoutes.some(route => req.originalUrl === route || req.originalUrl.startsWith(route));
                    
                    const challengeRoutes = ['/api/auth/mfa/challenge', '/api/auth/mfa/verify-recovery'];
                    if (isSensitive && !challengeRoutes.includes(req.originalUrl)) {
                        return res.status(403).json({ error: 'MFA verification required', requiresMfa: true });
                    }
                }
            }
        } catch (e) {
            console.error("Auth Middleware Firestore Error:", e.message);
        }

        req.user = user;
        next();
    });
};

const authenticateOptional = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        token = req.cookies.accessToken;
    }
    
    if (!token) {
        req.user = { email: 'guest', role: 'guest' };
        return next();
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            req.user = { email: 'guest', role: 'guest' };
        } else {
            req.user = user;
        }
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Admin access required' });
    }
};

module.exports = {
    authenticateToken,
    authenticateOptional,
    requireAdmin
};