const disposableDomains = [
    'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'yopmail.com', 
    'mailinator.com', 'throwawaymail.com', 'dispostable.com', 'temp-mail.org',
    'fakeinbox.com', 'sharklasers.com'
];

function validateEmail(email) {
    if (!email || typeof email !== 'string') {
        return { valid: false, error: 'Email is required' };
    }

    const lowerEmail = email.toLowerCase().trim();
    const domain = lowerEmail.split('@')[1];

    if (!domain) {
        return { valid: false, error: 'Invalid email format' };
    }

    if (disposableDomains.includes(domain)) {
        return { valid: false, error: 'Disposable email addresses are not allowed' };
    }

    return { valid: true };
}

module.exports = {
    validateEmail,
    disposableDomains
};