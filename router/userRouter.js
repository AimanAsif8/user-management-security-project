const express = require('express');
const userSchema = require('../model/userSchema');
const user = express.Router();

const userLoginControl = require('../controller/userController/loginController');
const userHomeControl = require('../controller/userController/homeController');

// 🆕 Import the JWT middleware
const verifyToken = require('../middleware/auth'); // Make sure the path is correct

user.get('/', userLoginControl.user);
user.get('/login', userLoginControl.login);

user.post('/login', userLoginControl.loginPost);

user.get('/register', userLoginControl.register);

user.post('/register', userLoginControl.registerPost);

user.get('/auth/google', userLoginControl.googleRender);
user.get('/auth/google/callback', userLoginControl.googleCallback);

// 🆕 Protect home route with verifyToken
user.get('/home', verifyToken, userHomeControl.home);

user.get('/logout', userLoginControl.logout);

module.exports = user;