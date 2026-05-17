const path = require('path');
const isCloudRun = process.env.K_SERVICE !== undefined;
const BASE_DIR = isCloudRun ? '/tmp' : path.join(__dirname, '../../');
const DATA_DIR = path.join(BASE_DIR, 'riser_data');

module.exports = {
    DATA_DIR,
    CHATS_DIR: path.join(DATA_DIR, 'chats'),
    CONFIG_FILE: path.join(DATA_DIR, 'config.json'),
    USERS_FILE: path.join(DATA_DIR, 'users.json')
};