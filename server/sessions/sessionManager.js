const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'risergpt-superkey-hdbf53ydshfsd';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'risergpt-refresh-superkey-jsd83';

function generateTokens(user, mfaVerified = false, sessionId = null) {
    const accessToken = jwt.sign(
        { email: user.email, role: user.role || 'user', uid: user.uid, mfaVerified, sessionId },
        JWT_SECRET,
        { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
        { email: user.email, role: user.role || 'user', uid: user.uid, mfaVerified, sessionId },
        JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
}

function setCookieTokens(res, accessToken, refreshToken) {
    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production' || true,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 mins
    });

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production' || true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
}

function clearCookieTokens(res) {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
}

module.exports = {
    generateTokens,
    setCookieTokens,
    clearCookieTokens,
    JWT_SECRET,
    JWT_REFRESH_SECRET
};