const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const auth = require('../middleware/auth');

const { envemail, envemailPassword, envgoogleClientId, jwtsecret } = require('../config');


const router = express.Router();
const client = new OAuth2Client(envgoogleClientId);

// Setup nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: envemail,

        pass: envemailPassword,
    },
});
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const payload = {
            user: {
                id: user.id,
            }
        };

        jwt.sign(payload, jwtsecret, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});
//rest password otp 
router.post('/reset-password', async (req, res) => {
    try {
        const { userId, otp, newPassword } = req.body;

        let user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ msg: 'User not found' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ msg: 'Invalid OTP' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        user.otp = null; // Clear OTP after resetting password
        await user.save();

        res.status(200).json({ msg: 'Password reset successful' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});





router.post('/google', async (req, res) => {
    try {
        const { token } = req.body;
        console.log(token);
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: envgoogleClientId,
        });
        const { name, email, sub: googleId } = ticket.getPayload();

        let user = await User.findOne({ email });
        if (!user) {
            user = new User({ name, email, googleId });
            await user.save();
        }

        const payload = {
            user: {
                id: user.id,
            },
        };

        jwt.sign(payload, jwtsecret, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
        });
    } catch (err) {
        console.error('Google auth error:', err.message);
        res.status(500).send('Server error');
    }
});
//forgot password
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'User not found' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Send OTP via email
        const mailOptions = {
            from: envemail,
            to: email,
            subject: 'Your OTP Code for Password Reset',
            text: `Your OTP code is ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                return res.status(500).json({ msg: 'Error sending email' });
            } else {
                console.log('Email sent: ' + info.response);
                user.otp = otp;
                user.save();
                res.status(200).json({ msg: 'OTP sent to email', userId: user.id });
            }
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


// Signup route
router.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ msg: 'Please provide all required fields: name, email, password' });
        }

        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Send OTP via email
        const mailOptions = {
            from: envemail,
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                return res.status(500).json({ msg: 'Error sending email' }); // Avoid sending response inside callback
            } else {
                console.log('Email sent: ' + info.response);
                res.status(200).json({ msg: 'OTP sent to email' }); // Move response outside callback
            }
        })

        // Save user with hashed password and OTP
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ name, email, password: hashedPassword, otp });
        await user.save();

        return res.status(200).json({ msg: 'OTP sent to email', userId: user.id });
    } catch (err) {
        console.error(err.message);
        return res.status(500).send('Server error');
    }
});

// Verify OTP route
router.post('/verify-otp', async (req, res) => {
    try {
        const { userId, otp } = req.body;

        let user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ msg: 'User not found' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ msg: 'Invalid OTP' });
        }

        user.otp = null; // Clear OTP after verification
        await user.save();

        res.status(200).json({ msg: 'OTP verified, you can now log in' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;
