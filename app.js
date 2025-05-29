const express = require('express');
const app = express();

const helmet = require('helmet');
app.use(helmet()); // Secure HTTP headers

const winston = require('winston'); // 🛡 Winston logger
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});
logger.info('Application started'); // Log app start

const session = require('express-session');
const dotenv = require('dotenv').config();
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const userRouter = require('./router/userRouter');
const adminRouter = require('./router/adminRouter');
const flash = require('connect-flash');
const mongodbConnection = require('./config/mongodb');
const nocache = require('nocache');
const passport = require('passport');
const cookieParser = require('cookie-parser');

// Port
const port = process.env.PORT || 3000;

// Connect DB
mongodbConnection();

// Middleware
app.use(flash());
app.use(nocache());

app.use('/images', express.static(path.join(__dirname, 'public', 'images')));
app.use('/style', express.static(path.join(__dirname, 'public', 'style')));
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: "your secret key",
    resave: false,
    saveUninitialized: true,
}));

app.use(cookieParser());

// Auth
app.use(passport.initialize());
app.use(passport.session());

// Layouts
app.use(expressLayouts);
app.set('layout', './layouts/layout');
app.set('view engine', 'ejs');

// Routes
app.use('/user', userRouter);
app.use('/admin', adminRouter);

// Default route
app.get('/', (req, res) => {
    logger.info('Redirected to login'); // Example log
    res.redirect("/user/login");
});

// 404
app.use("*", (req, res) => {
    logger.warn('404 - Page not found'); // Log missing route
    res.render('pageNotFound', { title: "Page not found" });
});

// Start Server
app.listen(port, (err) => {
    if (err) {
        logger.error(`Error during port listening: ${err}`);
    } else {
        logger.info(`Server running on http://localhost:${port}`);
        console.log(`Server running on http://localhost:${port}`);
    }
});