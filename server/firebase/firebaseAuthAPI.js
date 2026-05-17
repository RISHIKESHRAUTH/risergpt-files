const axios = require('axios');
const { admin, firebaseConfig } = require('./firebaseAdmin');

const API_KEY = firebaseConfig.apiKey;
const IDENTITY_TOOLKIT_URL = 'https://identitytoolkit.googleapis.com/v1/accounts';

async function signInWithPassword(email, password) {
    try {
        const response = await axios.post(`${IDENTITY_TOOLKIT_URL}:signInWithPassword?key=${API_KEY}`, {
            email,
            password,
            returnSecureToken: true
        });
        return response.data;
    } catch (error) {
        throw new Error(error.response?.data?.error?.message || 'Invalid email or password');
    }
}

async function signUp(email, password) {
    try {
        const response = await axios.post(`${IDENTITY_TOOLKIT_URL}:signUp?key=${API_KEY}`, {
            email,
            password,
            returnSecureToken: true
        });
        return response.data;
    } catch (error) {
        throw new Error(error.response?.data?.error?.message || 'Sign up failed');
    }
}

async function generateVerificationLink(email) {
    try {
        const link = await admin.auth().generateEmailVerificationLink(email);
        return link;
    } catch (error) {
        throw new Error('Failed to generate verification link');
    }
}

async function generatePasswordResetLink(email) {
    try {
        const link = await admin.auth().generatePasswordResetLink(email);
        return link;
    } catch (error) {
        throw new Error('Failed to generate reset link');
    }
}

module.exports = {
    signInWithPassword,
    signUp,
    generateVerificationLink,
    generatePasswordResetLink
};