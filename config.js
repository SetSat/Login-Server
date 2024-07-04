// config.js
require('dotenv').config({ path: './config/.env' });

module.exports = {
    envemail: process.env.EMAIL,
    envemailPassword: process.env.EMAIL_PASSWORD,
    envgoogleClientId: process.env.GOOGLE_CLIENT_ID,
    jwtsecret:process.env.JWT_SECRET
};
