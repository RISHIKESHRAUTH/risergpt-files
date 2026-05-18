require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const admin = require('firebase-admin');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const { body, validationResult } = require('express-validator');
const { validateEmail } = require('./server/verification/emailValidator');
const { sendVerificationEmail, sendLoginAlertEmail } = require('./server/email/emailService');
const otpRoutes = require('./server/auth/otpRoutes');

const firebaseConfig = require('./firebase-applet-config.json');

// Initialize Firebase Admin
try {
    if (!admin.apps.length) {
        admin.initializeApp({
            projectId: firebaseConfig.projectId,
        });
    }
} catch (e) {
    console.error('Firebase Admin initialization error:', e.message);
}

const app = express();

app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// --- SECURITY MIDDLEWARE ---
app.disable('x-powered-by');

// CORS configuration
const allowedOrigins = [
    'https://risergpt.qzz.io',
    /^http:\/\/localhost:\d+$/,
    /^http:\/\/127\.0\.0\.1:\d+$/,
    /^https:\/\/.*\.run\.app$/
];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const allowed = allowedOrigins.some(o => 
            typeof o === 'string' ? o === origin : o.test(origin)
        );
        if (allowed) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

// Helmet Configuration
app.use(helmet({
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
                "https://*.firebaseapp.com",
                "https://*.firebase.com",
                "https://*.googleapis.com"
            ],
            styleSrc: [
                "'self'", 
                "'unsafe-inline'", 
                "https://cdnjs.cloudflare.com", 
                "https://fonts.googleapis.com", 
                "https://www.gstatic.com"
            ],
            fontSrc: [
                "'self'", 
                "https://fonts.gstatic.com",
                "data:",
                "https://cdnjs.cloudflare.com"
            ],
            imgSrc: [
                "'self'", 
                "data:", 
                "blob:", 
                "https:", 
                "https://*.googleusercontent.com", 
                "https://www.gstatic.com",
                "https://*.pollinations.ai"
            ],
            connectSrc: [
                "'self'",
                "https://api.tavily.com",
                "https://api.groq.com",
                "https://api.x.ai",
                "https://generativelanguage.googleapis.com",
                "https://identitytoolkit.googleapis.com",
                "https://securetoken.googleapis.com",
                "https://apis.google.com",
                "https://accounts.google.com",
                "https://www.googleapis.com",
                "https://firebaseio.com",
                "https://*.firebaseio.com",
                "wss://*.firebaseio.com",
                "https://*.firebaseapp.com",
                "https://*.firebase.com",
                "https://*.googleapis.com",
                "https://www.gstatic.com",
                "https://*.gstatic.com",
                "https://cdnjs.cloudflare.com"
            ],
            frameSrc: [
                "'self'",
                "https://accounts.google.com",
                "https://apis.google.com",
                "https://*.firebaseapp.com",
                "https://*.firebase.com"
            ],
            childSrc: ["'self'", "blob:", "https://*.firebaseapp.com"],
            workerSrc: ["'self'", "blob:"]
        },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "unsafe-none" } // Changed from "same-origin-allow-popups" for better compatibility with Google Auth in some environments
}));

app.use(cookieParser());
app.use(express.json({ limit: '50mb' }));
app.use(mongoSanitize());
app.use(xss());

// Rate Limiters
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

app.use('/api/', globalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/users/admin-login', authLimiter);

// Remove dangerous public file access
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, fp) => {
        if (fp.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    }
}));

// --- LOAD ROUTES ---
const authRoutes = require('./server/auth/authRoutes');
app.use('/api/auth', authRoutes);
app.use('/api/auth/otp', otpRoutes);

// --- SETUP DIRECTORIES ---
const { DATA_DIR, CHATS_DIR, CONFIG_FILE, USERS_FILE } = require('./server/config/paths');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(CHATS_DIR)) fs.mkdirSync(CHATS_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));

function getUserChatDir(email) {
    let folderName = 'guest';
    if (email && email !== 'guest') {
        try {
            const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
            const user = users.find(u => u.email === email);
            if (user && user.name) {
                folderName = user.name.replace(/[^a-z0-9]/gi, '_').trim() || 'user';
            } else {
                folderName = email.replace(/[^a-z0-9]/gi, '_');
            }
        } catch (e) {
            folderName = String(email).replace(/[^a-z0-9]/gi, '_');
        }
    }
    const userDir = path.join(CHATS_DIR, folderName);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }
    return userDir;
}

const { authenticateToken, authenticateOptional, requireAdmin } = require('./server/middleware/authMiddleware');

// Default config setup
try {
    if (fs.existsSync(USERS_FILE)) {
        let usersData = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        let modified = false;
        usersData = usersData.map(u => {
            if (u.plan === 'Free' || u.plan === 'FREE') {
                u.plan = 'Muft Plan';
                modified = true;
            }
            return u;
        });
        if (modified) {
            fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2));
            console.log('Migrated old plan names to "Muft Plan"');
        }
    }
} catch (e) {
    console.error('Migration error:', e);
}

const defaultConfig = {
    announcement: { text: "", status: "inactive" },
    coupons: [],
    plans: [
        {
            id: "muft",
            name: "Muft Plan",
            price: 0,
            discount: 0,
            description: "Intelligence for everyday tasks (Free for everyone)",
            features: [
                "Access to RH-6",
                "Standard messaging",
                "Image analysis",
                "Unlimited Image Generations",
                "Limited memory & context"
            ],
            isHighlight: false
        },
        {
            id: "prarambh",
            name: "Prarambh Plan",
            price: 299,
            discount: 0,
            description: "Entry-level professional features",
            features: [
                "Fast Access to RH-6",
                "Priority messaging",
                "Image analysis",
                "Unlimited Image Generations",
                "Enhanced memory & context"
            ],
            isHighlight: true
        },
        {
            id: "tiranga",
            name: "Tiranga Plan",
            price: 1299,
            discount: 0,
            description: "Advanced intelligence and reasoning",
            features: [
                "RH-6 Advanced Model",
                "Extreme messaging speed",
                "Image analysis",
                "Unlimited Image Generations",
                "Max memory & context"
            ],
            isHighlight: false
        },
        {
            id: "bharat",
            name: "Bharat Plan",
            price: 15999,
            discount: 0,
            description: "Full potential of RiserGPT for enterprises",
            features: [
                "Full RH-6 Suite Access",
                "Unlimited everything",
                "Dedicated processing power",
                "Specialized image/video tools",
                "Enterprise level context"
            ],
            isHighlight: false
        }
    ]
};

if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(defaultConfig, null, 2));
}

// API Endpoint: Get Configuration
app.get('/api/config', (req, res) => {
    fs.readFile(CONFIG_FILE, 'utf8', (err, data) => {
        if (err) {
            console.error("Error reading config");
            return res.status(500).json({ error: 'Service temporarily unavailable' });
        }
        try {
            const config = JSON.parse(data);
            const merged = { ...defaultConfig, ...config };
            if(!merged.plans) merged.plans = defaultConfig.plans;
            res.json(merged);
        } catch (e) {
            res.json(defaultConfig);
        }
    });
});

// API Endpoint: Save Configuration (ADMIN ONLY)
app.post('/api/config', authenticateToken, requireAdmin, (req, res) => {
    const newConfig = req.body;
    fs.writeFile(CONFIG_FILE, JSON.stringify(newConfig, null, 2), (err) => {
        if (err) {
            console.error("Error writing config");
            return res.status(500).json({ error: 'Service temporarily unavailable' });
        }
        res.json({ success: true });
    });
});

// --- USER MANAGEMENT ENDPOINTS ---

app.post('/api/users/save', [
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('name').trim().isString().isLength({ min: 1, max: 100 }).withMessage('Name is required and must be under 100 characters'),
    body('password').optional({ checkFalsy: true }).isString().isLength({ min: 6, max: 100 }).withMessage('Password must be between 6 and 100 characters'),
    body('profileImage').optional({ checkFalsy: true }).isString().isLength({ max: 500 }),
    body('authProvider').optional({ checkFalsy: true }).isString().isLength({ max: 50 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        const emailValidation = validateEmail(req.body.email);
        if (!emailValidation.valid) {
            return res.status(400).json({ error: emailValidation.error });
        }

        const email = req.body.email;
        const safeData = {
            name: req.body.name,
            email: email,
            password: req.body.password,
            profileImage: req.body.profileImage || null,
            authProvider: req.body.authProvider || 'local'
        };

        let users = [];
        if (fs.existsSync(USERS_FILE)) {
            users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        }
        
        const existingIndex = users.findIndex(u => u.email === email);
        
        let savedUser;
        if (existingIndex > -1) {
            // Update existing
            if (safeData.password) {
                // If password was provided and differs, hash it
                safeData.password = await bcrypt.hash(safeData.password, 10);
            } else {
                // otherwise keep existing password
                safeData.password = users[existingIndex].password;
            }
            
            // Explicitly only update allowed fields
            users[existingIndex].name = safeData.name;
            users[existingIndex].password = safeData.password;
            if (safeData.profileImage) users[existingIndex].profileImage = safeData.profileImage;
            if (safeData.authProvider) users[existingIndex].authProvider = safeData.authProvider;
            
            savedUser = users[existingIndex];
        } else {
            // New User
            if (!req.body.password) return res.status(400).json({ error: 'Password required' });
            safeData.password = await bcrypt.hash(safeData.password, 10);
            
            const newUser = {
                id: Date.now().toString(),
                email: safeData.email,
                name: safeData.name,
                password: safeData.password,
                profileImage: safeData.profileImage,
                authProvider: safeData.authProvider,
                isBanned: false,
                verified: false,
                role: 'user', // explicitly hardcode role to prevent injection
                plan: "Muft Plan",
                planStatus: "active",
                planExpiry: "never",
                daysRemaining: "unlimited",
                createdAt: new Date().toISOString(),
                securityLogs: [],
                trustedDevices: [],
                mfaEnabled: false,
                lastLogin: null,
                otpCreatedAt: null
            };
            users.push(newUser);
            savedUser = newUser;
        }
        
        // Ensure user is verified before issuing token
        if (!savedUser.verified) {
            const now = Date.now();
            if (!savedUser.lastVerificationAttempt || (now - savedUser.lastVerificationAttempt) > 60000) {
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                savedUser.otpHash = await bcrypt.hash(otp, 10);
                savedUser.otpCreatedAt = now;
                savedUser.lastVerificationAttempt = now;
                savedUser.verificationPending = true;
                await sendVerificationEmail(savedUser.email, otp);
            }
            fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
            return res.json({ success: true, requiresVerification: true, message: 'Please verify your email.' });
        }

        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        
        const userForClient = { ...savedUser };
        delete userForClient.password;
        
        const token = jwt.sign({ email: savedUser.email, role: 'user' }, JWT_SECRET);
        res.json({ success: true, token, user: userForClient });
    } catch (error) {
        console.error('Save User Error:', error);
        res.status(500).json({ error: 'Service temporarily unavailable' });
    }
});

app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const user = users.find(u => u.email === email);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        let passwordMatches = false;
        
        if (user.password.startsWith('$2b$')) {
            // It's a bcrypt hash
            passwordMatches = await bcrypt.compare(password, user.password);
        } else {
            // Old plain text password migration
            if (user.password === password) {
                passwordMatches = true;
                // Migrate to bcrypt immediately
                user.password = await bcrypt.hash(password, 10);
                fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
                console.log(`Migrated password for user ${user.email}`);
            }
        }
        
        if (passwordMatches) {
            if (user.isBanned) return res.status(403).json({ error: 'This account is banned.' });
            
            if (!user.verified) {
                const now = Date.now();
                if (!user.lastVerificationAttempt || (now - user.lastVerificationAttempt) > 60000) {
                    const otp = Math.floor(100000 + Math.random() * 900000).toString();
                    user.otpHash = await bcrypt.hash(otp, 10);
                    user.otpCreatedAt = now;
                    user.lastVerificationAttempt = now;
                    user.verificationPending = true;
                    await sendVerificationEmail(user.email, otp);
                    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
                }
                return res.status(403).json({ error: 'Please verify your email address.', requiresVerification: true });
            }
            
            user.lastLogin = new Date().toISOString();
            fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

            // Send login alert asynchronously
            sendLoginAlertEmail(user.email, user.name).catch(err => console.error('Error sending login alert', err));

            const userForClient = { ...user };
            delete userForClient.password;
            const token = jwt.sign({ email: user.email, role: 'user' }, JWT_SECRET);
            res.json({ success: true, user: userForClient, token });
        } else {
            res.status(401).json({ error: 'Invalid email or password' });
        }
    } catch (error) {
        console.error('Login Error');
        res.status(500).json({ error: 'Service temporarily unavailable' });
    }
});

// Admin Login
app.post('/api/users/admin-login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'rishiop' && password === 'R20100910r#') {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ success: true, token });
    } else {
        res.status(401).json({ error: 'Invalid admin credentials' });
    }
});

app.post('/api/users/save-bulk', authenticateToken, requireAdmin, (req, res) => {
    try {
        const users = req.body;
        if (!Array.isArray(users)) return res.status(400).json({ error: 'Data must be an array' });
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        res.json({ success: true });
    } catch (error) {
        console.error("Bulk save error");
        res.status(500).json({ error: 'Service temporarily unavailable' });
    }
});

app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        res.json(users);
    } catch (error) {
        console.error("Fetch users error");
        res.status(500).json({ error: 'Service temporarily unavailable' });
    }
});

// --- CHAT STORAGE ENDPOINTS ---

const CHAT_INDEX_NAME = 'index.riser';

function readChatIndex(userDir) {
    const indexPath = path.join(userDir, CHAT_INDEX_NAME);
    let indexData = { NEXT_CHAT_ID: 1, CACHE: {} };
    if (fs.existsSync(indexPath)) {
        try {
            const content = fs.readFileSync(indexPath, 'utf8');
            indexData = JSON.parse(content);
        } catch(e) {}
    }
    
    // Repair CACHE if any .rchat files exist but aren't in index
    let repaired = false;
    if (fs.existsSync(userDir)) {
        const files = fs.readdirSync(userDir);
        for (const file of files) {
            if (file.endsWith('.rchat')) {
                // Find ID from filename or content
                // the filename is YYYY-MM-DD_chat-N.rchat
                const parts = file.split('_');
                if (parts.length >= 2) {
                    const idPart = parts.slice(1).join('_').replace('.rchat', '');
                    if (!indexData.CACHE[idPart] || indexData.CACHE[idPart] !== file) {
                        indexData.CACHE[idPart] = file;
                        repaired = true;
                        
                        // Also update NEXT_CHAT_ID if it's chat-XYZ
                        if (idPart.startsWith('chat-')) {
                            const num = parseInt(idPart.substring(5), 10);
                            if (!isNaN(num) && num >= indexData.NEXT_CHAT_ID) {
                                indexData.NEXT_CHAT_ID = num + 1;
                            }
                        }
                    }
                }
            }
        }
    }
    
    if (repaired) {
        writeChatIndex(userDir, indexData);
    }
    return indexData;
}

function writeChatIndex(userDir, indexData) {
    const indexPath = path.join(userDir, CHAT_INDEX_NAME);
    // Write atomically
    const tempPath = indexPath + '.tmp';
    fs.writeFileSync(tempPath, JSON.stringify(indexData, null, 2), 'utf8');
    fs.renameSync(tempPath, indexPath);
}

function serializeRChat(chat, currentUsername) {
    let output = `CHAT_ID: ${chat.id}\n`;
    output += `TITLE: ${chat.title || 'New Chat'}\n`;
    output += `USER: ${currentUsername}\n`;
    output += `MODEL: ${chat.model || 'RH-6'}\n`;
    output += `CREATED: ${new Date(chat.timestamp || Date.now()).toISOString().split('T')[0]}\n`;
    output += `TIMESTAMP: ${chat.timestamp || Date.now()}\n`;
    output += `DELETED: ${chat.deleted ? 'true' : 'false'}\n`;
    output += `PINNED: ${chat.pinned ? 'true' : 'false'}\n`;
    output += `PRIORITIZED: ${chat.prioritized ? 'true' : 'false'}\n`;
    output += `\n`;

    if (chat.messages && chat.messages.length > 0) {
        for (const msg of chat.messages) {
            output += `[${msg.role.toUpperCase()}]\n`;
            if (msg.image) output += `[IMAGE]: ${msg.image}\n`;
            if (msg.generatedImage) output += `[GENERATED_IMAGE]: ${msg.generatedImage}\n`;
            if (msg.imgRatioClass) output += `[IMG_RATIO]: ${msg.imgRatioClass}\n`;
            if (msg.video) output += `[VIDEO]: ${msg.video}\n`;
            if (msg.generatedVideo) output += `[GENERATED_VIDEO]: ${msg.generatedVideo}\n`;
            if (msg.isGeneratingImage) output += `[IS_GENERATING]: true\n`;
            if (msg.prioritized) output += `[PRIORITIZED]: true\n`;
            if (msg.versions) output += `[VERSIONS]: ${JSON.stringify(msg.versions)}\n`;
            if (msg.currentVersion !== undefined) output += `[CURRENT_VERSION]: ${msg.currentVersion}\n`;
            
            let content = msg.content || '';
            output += `${content.trim()}\n\n`;
        }
    }
    return output;
}

function parseRChat(content) {
    const lines = content.split('\n');
    let chat = { messages: [] };
    let mode = 'header';
    let currentRole = null;
    let currentMsgMeta = {};
    let currentContent = [];

    const flushMessage = () => {
        if (currentRole) {
            chat.messages.push({
                id: Math.random().toString(36).substr(2, 9),
                role: currentRole,
                content: currentContent.join('\n').trim(),
                ...currentMsgMeta
            });
        }
    };

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (mode === 'header') {
            if (line.startsWith('CHAT_ID: ')) chat.id = line.substring(9).trim();
            else if (line.startsWith('TITLE: ')) chat.title = line.substring(7).trim();
            else if (line.startsWith('USER: ')) chat.owner = line.substring(6).trim();
            else if (line.startsWith('MODEL: ')) chat.model = line.substring(7).trim();
            else if (line.startsWith('TIMESTAMP: ')) chat.timestamp = parseInt(line.substring(11).trim(), 10);
            else if (line.startsWith('DELETED: ')) chat.deleted = line.substring(9).trim() === 'true';
            else if (line.startsWith('PINNED: ')) chat.pinned = line.substring(8).trim() === 'true';
            else if (line.startsWith('PRIORITIZED: ')) chat.prioritized = line.substring(13).trim() === 'true';
            else if (line === '') {
                // Skip empty lines in header
            } else if (line === '[USER]' || line === '[ASSISTANT]' || line === '[SYSTEM]') {
                mode = 'body';
                currentRole = line.substring(1, line.length - 1).toLowerCase();
                currentMsgMeta = {};
            }
        } else if (mode === 'body') {
            if (line === '[USER]' || line === '[ASSISTANT]' || line === '[SYSTEM]') {
                flushMessage();
                currentRole = line.substring(1, line.length - 1).toLowerCase();
                currentContent = [];
                currentMsgMeta = {};
            } else if (line.startsWith('[IMAGE]: ')) {
                currentMsgMeta.image = line.substring(9).trim();
            } else if (line.startsWith('[GENERATED_IMAGE]: ')) {
                currentMsgMeta.generatedImage = line.substring(19).trim();
            } else if (line.startsWith('[IMG_RATIO]: ')) {
                currentMsgMeta.imgRatioClass = line.substring(13).trim();
            } else if (line.startsWith('[VIDEO]: ')) {
                currentMsgMeta.video = line.substring(9).trim();
            } else if (line.startsWith('[GENERATED_VIDEO]: ')) {
                currentMsgMeta.generatedVideo = line.substring(19).trim();
            } else if (line === '[IS_GENERATING]: true') {
                currentMsgMeta.isGeneratingImage = true;
            } else if (line === '[PRIORITIZED]: true') {
                currentMsgMeta.prioritized = true;
            } else if (line.startsWith('[VERSIONS]: ')) {
                try { currentMsgMeta.versions = JSON.parse(line.substring(12).trim()); } catch(e) {}
            } else if (line.startsWith('[CURRENT_VERSION]: ')) {
                currentMsgMeta.currentVersion = parseInt(line.substring(19).trim(), 10);
            } else {
                currentContent.push(line);
            }
        }
    }
    flushMessage();
    return chat;
}

function migrateOldJsonToRChat(userDir, userEmail) {
    if (!fs.existsSync(userDir)) return;
    const files = fs.readdirSync(userDir);
    let indexData = readChatIndex(userDir);
    let migrated = false;

    for (const file of files) {
        if (file.endsWith('.json') && file !== CHAT_INDEX_NAME) {
            try {
                const oldPath = path.join(userDir, file);
                const data = JSON.parse(fs.readFileSync(oldPath, 'utf8'));
                if (!data.id) continue;
                
                // Keep the same backend ID generation logic
                let chatIdNum = indexData.NEXT_CHAT_ID++;
                let newId = `chat-${chatIdNum}`;
                data.id = newId;

                const dateStr = new Date(data.timestamp || Date.now()).toISOString().split('T')[0];
                const newFilename = `${dateStr}_${newId}.rchat`;
                const newPath = path.join(userDir, newFilename);

                fs.writeFileSync(newPath, serializeRChat(data, userEmail), 'utf8');
                fs.unlinkSync(oldPath);
                
                indexData.CACHE[newId] = newFilename;
                migrated = true;
            } catch (e) {}
        }
    }
    if (migrated) {
        writeChatIndex(userDir, indexData);
    }
}

app.get('/api/chats', authenticateOptional, (req, res) => {
    const userEmail = req.user.email;
    if (!userEmail || userEmail === 'guest') return res.json([]);
    
    const userDir = getUserChatDir(userEmail);
    // Auto-migrate old .json
    migrateOldJsonToRChat(userDir, userEmail);
    
    let allChats = [];
    const indexData = readChatIndex(userDir);
    
    if (fs.existsSync(userDir)) {
        const files = fs.readdirSync(userDir);
        for (const file of files) {
            if (file.endsWith('.rchat')) {
                try {
                    const content = fs.readFileSync(path.join(userDir, file), 'utf8');
                    const data = parseRChat(content);
                    if (!data.deleted) {
                        allChats.push(data);
                    }
                } catch (e) {
                    console.error('Error parsing .rchat file', e);
                }
            }
        }
    }
    
    allChats.sort((a, b) => b.timestamp - a.timestamp);
    res.json(allChats);
});

app.get('/api/chats/:id', authenticateOptional, (req, res) => {
    const requestedId = path.basename(req.params.id); 
    const userEmail = req.user.email;
    
    const userDir = getUserChatDir(userEmail);
    const indexData = readChatIndex(userDir);
    const filename = indexData.CACHE[requestedId];
    
    if (!filename) return res.status(404).json({ error: 'Chat not found in index' });
    
    const chatFile = path.join(userDir, filename);
    if (!fs.existsSync(chatFile)) return res.status(404).json({ error: 'Chat file missing' });

    fs.readFile(chatFile, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Read error' });
        try {
            const chat = parseRChat(data);
            if (chat.deleted) return res.status(404).json({ error: 'Chat has been removed' });
            if (chat.shared || chat.owner === userEmail || req.user.role === 'admin') {
                res.json(chat);
            } else {
                res.status(403).json({ error: 'Access denied' });
            }
        } catch (e) {
            res.status(500).json({ error: 'Parse error' });
        }
    });
});

app.post('/api/chats', authenticateOptional, (req, res) => {
    const chat = req.body;
    if (!chat.id) return res.status(400).json({ error: 'Chat ID required' });
    
    const requestedEmail = req.user.email;
    if(chat.owner !== requestedEmail && req.user.role !== 'admin') {
        chat.owner = requestedEmail;
    }

    const userDir = getUserChatDir(chat.owner);
    let indexData = readChatIndex(userDir);
    
    let isNewId = false;
    let assignedId = chat.id;

    // Check if ID is new (e.g. timestamp from frontend)
    if (!chat.id.startsWith('chat-') || !indexData.CACHE[chat.id]) {
        isNewId = true;
        assignedId = `chat-${indexData.NEXT_CHAT_ID++}`;
        chat.id = assignedId;
    }

    const dateStr = new Date(chat.timestamp || Date.now()).toISOString().split('T')[0];
    const filename = `${dateStr}_${assignedId}.rchat`;
    const chatFile = path.join(userDir, filename);
    
    // If it already had a different filename, remove old file 
    // (Wait, we can just let it exist or cleanup old ones, but to be safe removing old filename is good)
    if (!isNewId && indexData.CACHE[assignedId] && indexData.CACHE[assignedId] !== filename) {
        const oldFile = path.join(userDir, indexData.CACHE[assignedId]);
        if (fs.existsSync(oldFile)) fs.unlinkSync(oldFile);
    }
    
    indexData.CACHE[assignedId] = filename;

    // Soft delete support: if it's explicitly deleted from frontend
    // but frontend uses DELETE endpoint.
    
    const rchatContent = serializeRChat(chat, chat.owner);
    
    // Atomic write
    const tempPath = chatFile + '.tmp';
    fs.writeFile(tempPath, rchatContent, 'utf8', (err) => {
        if (err) return res.status(500).json({ error: 'Service temporarily unavailable' });
        fs.renameSync(tempPath, chatFile);
        writeChatIndex(userDir, indexData);
        res.json({ success: true, assignedId: isNewId ? assignedId : undefined });
    });
});

app.delete('/api/chats/:id', authenticateOptional, (req, res) => {
    const requestedId = path.basename(req.params.id);
    const userEmail = req.user.email;
    
    const userDir = getUserChatDir(userEmail);
    const indexData = readChatIndex(userDir);
    const filename = indexData.CACHE[requestedId];
    
    if (!filename) return res.status(404).json({ error: 'Not found' });
    const chatFile = path.join(userDir, filename);
    if (!fs.existsSync(chatFile)) return res.status(404).json({ error: 'File not found' });

    try {
        const content = fs.readFileSync(chatFile, 'utf8');
        const chat = parseRChat(content);
        if (chat.owner !== userEmail && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // SOFT DELETE
        chat.deleted = true;
        
        // ensure .deleted directory
        const delDir = path.join(userDir, '.deleted');
        if (!fs.existsSync(delDir)) fs.mkdirSync(delDir);
        
        // Atomic write back to main & move
        const newContent = serializeRChat(chat, chat.owner);
        const delPath = path.join(delDir, filename);
        fs.writeFileSync(delPath, newContent, 'utf8');
        
        // Remove from active
        fs.unlinkSync(chatFile);
        
        // Optional: remove from array/cache? We keep it in cache or remove?
        delete indexData.CACHE[requestedId];
        writeChatIndex(userDir, indexData);
        
    } catch(e) {
        return res.status(500).json({ error: 'Parse error' });
    }

    res.json({ success: true });
});

// --- API PROXY ENDPOINTS ---

const MODEL_MAP = {
    'RH-6': 'llama-3.3-70b-versatile',
    'RH-DEV-4': 'qwen/qwen3-32b',
    'RH-IMG-3': 'risergpt-vision-engine',
    'RH-VDO-1': 'ByteDance/Seedance-1.0-lite'
};

app.post('/api/chat', authenticateOptional, async (req, res) => {
    const { model, messages, stream } = req.body;

    if (model === 'RH-IMG-3') {
        const lastMessage = messages[messages.length - 1].content;
        const proxiedUrl = `/api/image-proxy?prompt=${encodeURIComponent(lastMessage)}`;
        
        if (stream) {
            res.setHeader('Content-Type', 'text/event-stream');
            res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: "✨ **RH-IMG-3** is initializing neural painting...\n\n" } }] })}\n\n`);
            res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: `![Generated Image](${proxiedUrl})` } }] })}\n\n`);
            res.write('data: [DONE]\n\n');
            return res.end();
        } else {
            return res.json({ choices: [{ message: { content: `![Generated Image](${proxiedUrl})` } }] });
        }
    }

    if (model === 'RH-VDO-1') {
        const responseText = "🎥 **Status: Under Development**\n\nThe RiserGPT Video Engine (Seedance-1.0-lite) is currently being optimized for cinematic 4K production. This feature will be available in the next major update. Stay tuned!";
        if (stream) {
            res.setHeader('Content-Type', 'text/event-stream');
            res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: responseText } }] })}\n\n`);
            res.write('data: [DONE]\n\n');
            return res.end();
        } else {
            return res.json({ choices: [{ message: { content: responseText } }] });
        }
    }

    let apiKey = process.env.GROQ_API_KEY;
    let apiUrl = 'https://api.groq.com/openai/v1/chat/completions';
    const groqModel = MODEL_MAP[model] || model;
    
    if (groqModel.startsWith('grok-')) {
        apiKey = process.env.XAI_API_KEY;
        apiUrl = 'https://api.x.ai/v1/chat/completions';
    }

    if (!apiKey) {
        return res.status(500).json({ error: 'Service temporarily unavailable' });
    }

    try {
        const response = await axios({
            method: 'post',
            url: apiUrl,
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            data: {
                model: groqModel,
                messages: messages,
                stream: stream || false
            },
            responseType: stream ? 'stream' : 'json'
        });

        if (stream) {
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            response.data.pipe(res);
        } else {
            res.json(response.data);
        }
    } catch (error) {
        console.error('API Error:', error.message);
        res.status(500).json({ error: 'Service temporarily unavailable' });
    }
});

// Search Routing (Tavily)
app.post('/api/search', authenticateOptional, async (req, res) => {
    const { query } = req.body;
    const apiKey = process.env.TAVILY_API_KEY;

    if (!apiKey) return res.status(500).json({ error: 'Service temporarily unavailable' });

    try {
        const response = await axios.post('https://api.tavily.com/search', {
            api_key: apiKey,
            query: query,
            search_depth: "smart",
            include_answer: true,
            max_results: 5
        });
        res.json(response.data);
    } catch (error) {
        console.error('Search Error:', error.message);
        res.status(500).json({ error: 'Service temporarily unavailable' });
    }
});

app.get('/api/image-proxy', async (req, res) => {
    const { prompt } = req.query;
    if (!prompt) return res.status(400).send('Prompt required');
    const width = 1024, height = 1024;
    const seed = Math.floor(Math.random() * 9999999);
    
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=31536000');

    const modelsToTry = ['flux', 'flux-realism', 'turbo', 'default'];

    const generateUrl = (m) => `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt)}?width=${width}&height=${height}&seed=${seed}&nologo=true&model=${m}`;

    for (const model of modelsToTry) {
        console.log(`[RH-IMG-3] Attempting generation with model: ${model}`);
        try {
            const response = await axios({
                url: generateUrl(model),
                method: 'GET',
                responseType: 'arraybuffer',
                timeout: 20000,
                validateStatus: null
            });

            const contentType = response.headers['content-type'] || '';
            const size = response.data ? response.data.length : 0;

            if (response.status === 200 && contentType.startsWith('image/') && size > 0) {
                console.log(`[RH-IMG-3] Success: Model ${model} | Mime: ${contentType} | Size: ${size} bytes`);
                res.setHeader('Content-Type', contentType);
                res.setHeader('Content-Length', size);
                return res.send(Buffer.from(response.data));
            } else {
                console.log(`[RH-IMG-3] Failed with Model ${model}: Status ${response.status} | Content-Type: ${contentType} | Size: ${size}`);
            }
        } catch (e) {
            console.error(`[RH-IMG-3] Error with Model ${model}:`, e.message);
        }
    }
    
    console.error("[RH-IMG-3] All models failed. Returning 500 Error.");
    res.status(500).send('Service temporarily unavailable');
});

// Start the server
app.get('*', (req, res) => {
    if (req.path.startsWith('/api')) {
        return res.status(404).json({ error: 'Not Found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`RiserGPT Secure Server running on port ${PORT}`);
});