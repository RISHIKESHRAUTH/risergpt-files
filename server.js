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
                "https://*.googleapis.com"
            ],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com", "https://www.gstatic.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "blob:", "https:", "https://*.googleusercontent.com", "https://www.gstatic.com"],
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
                "https://*.firebaseapp.com",
                "https://*.firebaseio.com",
                "wss://*.firebaseio.com",
                "https://www.gstatic.com"
            ],
            frameSrc: [
                "'self'",
                "https://accounts.google.com",
                "https://apis.google.com",
                "https://*.firebaseapp.com"
            ],
            childSrc: ["'self'", "blob:", "https://*.firebaseapp.com"],
            workerSrc: ["'self'", "blob:"]
        },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }
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

app.get('/api/chats', authenticateOptional, (req, res) => {
    const userEmail = req.user.email;
    if (!userEmail || userEmail === 'guest') return res.json([]);
    
    const userDir = getUserChatDir(userEmail);
    let allChats = [];
    
    if (fs.existsSync(userDir)) {
        const files = fs.readdirSync(userDir);
        for (const file of files) {
            if (file.endsWith('.json')) {
                try {
                    const data = JSON.parse(fs.readFileSync(path.join(userDir, file), 'utf8'));
                    allChats.push(data);
                } catch (e) {
                    console.error('Error parsing chat file');
                }
            }
        }
    }
    
    // Fallback sync
    if (fs.existsSync(CHATS_DIR)) {
        const files = fs.readdirSync(CHATS_DIR);
        for (const file of files) {
            if (file.endsWith('.json')) {
                try {
                    const data = JSON.parse(fs.readFileSync(path.join(CHATS_DIR, file), 'utf8'));
                    if (data.owner === userEmail && !allChats.find(c => c.id === data.id)) {
                        allChats.push(data);
                    }
                } catch (e) {}
            }
        }
    }
    
    allChats.sort((a, b) => b.timestamp - a.timestamp);
    res.json(allChats);
});

app.get('/api/chats/:id', authenticateOptional, (req, res) => {
    const chatId = path.basename(req.params.id); // Prevent path traversal
    const userEmail = req.user.email;
    
    const userDir = getUserChatDir(userEmail);
    let chatFile = path.join(userDir, `${chatId}.json`);
    
    if (!fs.existsSync(chatFile)) {
        const fallbackPath = path.join(CHATS_DIR, `${chatId}.json`);
        if (fs.existsSync(fallbackPath)) {
            chatFile = fallbackPath;
        } else {
            return res.status(404).json({ error: 'Chat not found' });
        }
    }

    fs.readFile(chatFile, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Read error' });
        try {
            const chat = JSON.parse(data);
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
    const chatId = path.basename(chat.id); // Prevent path traversal
    
    const requestedEmail = req.user.email;
    if(chat.owner !== requestedEmail && req.user.role !== 'admin') {
        chat.owner = requestedEmail; // Force ownership to the authenticated user
    }

    const userDir = getUserChatDir(chat.owner);
    const chatFile = path.join(userDir, `${chatId}.json`);
    
    if (fs.existsSync(chatFile)) {
        try {
            const existingData = JSON.parse(fs.readFileSync(chatFile, 'utf8'));
            if (existingData.owner && existingData.owner !== chat.owner && req.user.role !== 'admin') {
                return res.status(403).json({ error: 'Access denied' });
            }
        } catch(e) {}
    }

    fs.writeFile(chatFile, JSON.stringify(chat, null, 2), (err) => {
        if (err) return res.status(500).json({ error: 'Service temporarily unavailable' });
        res.json({ success: true });
    });
});

app.delete('/api/chats/:id', authenticateOptional, (req, res) => {
    const chatId = path.basename(req.params.id);
    const userEmail = req.user.email;
    
    const userDir = getUserChatDir(userEmail);
    let chatFile = path.join(userDir, `${chatId}.json`);
    
    if (!fs.existsSync(chatFile)) {
        const fallbackPath = path.join(CHATS_DIR, `${chatId}.json`);
        if (fs.existsSync(fallbackPath)) {
            chatFile = fallbackPath;
        } else {
            return res.status(404).json({ error: 'Not found' });
        }
    }

    try {
        const existingData = JSON.parse(fs.readFileSync(chatFile, 'utf8'));
        if (existingData.owner !== userEmail && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
    } catch(e) {
        return res.status(500).json({ error: 'Parse error' });
    }

    fs.unlink(chatFile, (err) => {
        if (err) return res.status(500).json({ error: 'Service temporarily unavailable' });
        res.json({ success: true });
    });
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
    
    const primaryModel = 'flux-realism';
    const fallbackModel = 'turbo';

    const generateUrl = (m) => `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt)}?width=${width}&height=${height}&seed=${seed}&nologo=true&model=${m}`;

    try {
        const response = await axios({
            url: generateUrl(primaryModel),
            method: 'GET',
            responseType: 'stream',
            timeout: 15000
        });
        res.setHeader('Content-Type', response.headers['content-type']);
        response.data.pipe(res);
    } catch (e) {
        console.error("Primary image failed");
        try {
            const fallbackResponse = await axios({
                url: generateUrl(fallbackModel),
                method: 'GET',
                responseType: 'stream'
            });
            res.setHeader('Content-Type', fallbackResponse.headers['content-type']);
            fallbackResponse.data.pipe(res);
        } catch (e2) {
            res.status(500).send('Service temporarily unavailable');
        }
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`RiserGPT Secure Server running on port ${PORT}`);
});