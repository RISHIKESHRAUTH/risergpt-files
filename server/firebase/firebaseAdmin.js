const admin = require('firebase-admin');
const firebaseConfig = require('../../firebase-applet-config.json');

try {
    if (!admin.apps.length) {
        admin.initializeApp({
            projectId: firebaseConfig.projectId,
        });
    }
} catch (error) {
    console.error('Firebase Admin initialization error:', error);
}

module.exports = { admin, firebaseConfig };