const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 200, 
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 15,
    message: { error: 'Too many attempts, please try again after 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
});

module.exports = {
    globalLimiter,
    authLimiter,
    helmetConfig: helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "'unsafe-eval'",
                    "https://cdnjs.cloudflare.com",
                    "https://cdn.jsdelivr.net",
                    "https://www.gstatic.com",
                    "https://apis.google.com",
                    "https://accounts.google.com",
                    "https://risergpt-fb614.firebaseapp.com"
                ],
                styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
                fontSrc: ["'self'", "https://fonts.gstatic.com"],
                imgSrc: ["'self'", "data:", "blob:", "https:"],
                connectSrc: [
                    "'self'",
                    "https://api.tavily.com",
                    "https://api.groq.com",
                    "https://api.x.ai",
                    "https://identitytoolkit.googleapis.com",
                    "https://securetoken.googleapis.com",
                    "https://apis.google.com",
                    "https://accounts.google.com",
                    "https://www.googleapis.com",
                    "https://risergpt-fb614.firebaseapp.com",
                    "https://*.firebaseio.com",
                    "wss://*.firebaseio.com",
                    "https://www.gstatic.com"
                ],
                frameSrc: [
                  "'self'",
                  "https://accounts.google.com",
                  "https://apis.google.com",
                  "https://risergpt-fb614.firebaseapp.com"
                ],
                childSrc: ["'self'", "blob:", "https://risergpt-fb614.firebaseapp.com"],
                workerSrc: ["'self'", "blob:"]
            },
        },
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }
    }),
    mongoSanitize: mongoSanitize(),
    xss: xss()
};