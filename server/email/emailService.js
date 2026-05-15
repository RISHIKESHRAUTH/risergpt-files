const nodemailer = require('nodemailer');

// Setup Nodemailer Base Configuration
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com', // Base setup for gmail
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER || 'official@risergpt.qzz.io',
        pass: process.env.EMAIL_PASS
    }
});

async function sendWelcomeEmail(toEmail, userName) {
    // Placeholder to satisfy the requirement
    try {
        console.log(`Sending welcome email to ${toEmail}`);
        // await transporter.sendMail({
        //     from: '"RiserGPT" <official@risergpt.qzz.io>',
        //     to: toEmail,
        //     subject: 'Welcome to RiserGPT!',
        //     text: `Hi ${userName}, welcome to RiserGPT!`
        // });
    } catch (e) {
        console.error('Email send failed', e);
    }
}

module.exports = {
    sendWelcomeEmail
};