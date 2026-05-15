const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../sessions/sessionManager');

const authenticateToken = (req, res, next) => {
    let token = req.cookies.accessToken;
    
    if (!token) {
        const authHeader = req.headers['authorization'];
        token = authHeader && authHeader.split(' ')[1];
    }
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

const authenticateOptional = (req, res, next) => {
    let token = req.cookies.accessToken;
    
    if (!token) {
        const authHeader = req.headers['authorization'];
        token = authHeader && authHeader.split(' ')[1];
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