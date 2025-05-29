const jwt = require('jsonwebtoken'); // Add at the top with other imports
const validator = require('validator');
const userSchema = require("../../model/userSchema");
const bcrypt = require('bcrypt');
const passport = require('passport');
require('../../service/auth');

// ========================== USER LANDING ================================
const user = (req, res) => {
    try {
        res.redirect('/user/login');
    } catch (err) {
        console.log('Error During user route');
    }
};

// ========================== LOGIN PAGE ================================
const login = (req, res) => {
    try {
        if (req.session.user) {
            res.redirect('/user/home');
        } else {
            res.render('user/login', { title: "Login", alertMessage: req.flash('errorMessage') });
        }
    } catch (err) {
        console.log(`Error on login page render ${err}`);
    }
};

// ========================== LOGIN POST ================================
const loginPost = async (req, res) => {
    try {
        const email = validator.trim(req.body.email);
        const password = req.body.password;

        const checkUser = await userSchema.findOne({ email });
        if (!checkUser) {
            req.flash('errorMessage', 'Invalid username or password');
            return res.redirect('/user/login');
        }

        const passwordCheck = await bcrypt.compare(password, checkUser.password);
        if (!passwordCheck) {
            req.flash('errorMessage', 'Invalid username or password');
            return res.redirect('/user/login');
        }

        // ✅ Create JWT Token
        const token = jwt.sign({ id: checkUser._id }, 'your-secret-key', { expiresIn: '1h' });

        // ✅ Store in session
        req.session.user = checkUser.email;
        req.session.token = token;

        return res.redirect('/user/home');

    } catch (err) {
        console.log(`Error on login Post ${err}`);
        req.flash('errorMessage', 'Login failed');
        return res.redirect('/user/login');
    }
};

// ========================== REGISTER PAGE ================================
const register = (req, res) => {
    try {
        if (req.session.user) {
            res.redirect('/user/home');
        } else {
            res.render('user/register', {
                title: "Register",
                alertMessage: req.flash('successMessage') || req.flash('errorMessage')
            });
        }

    } catch (err) {
        console.log(`Error rendering register page ${err}`);
    }
};

// ========================== REGISTER POST ================================
const registerPost = async (req, res) => {
    try {
        // Clean and validate inputs
        const name = validator.trim(validator.escape(req.body.name));
        const email = validator.trim(req.body.email);
        const password = req.body.password;

        // Validation
        if (!validator.isEmail(email)) {
            req.flash('errorMessage', '❌ Invalid email address');
            return res.redirect('/user/register');
        }

        if (!validator.isLength(name, { min: 3 })) {
            req.flash('errorMessage', '❌ Name must be at least 3 characters');
            return res.redirect('/user/register');
        }

        if (!validator.isStrongPassword(password, {
            minLength: 6, minLowercase: 1, minUppercase: 0, minNumbers: 1, minSymbols: 0
        })) {
            req.flash('errorMessage', '❌ Password should be at least 6 characters and contain a number');
            return res.redirect('/user/register');
        }

        const existingUser = await userSchema.findOne({ email });
        if (existingUser) {
            req.flash('errorMessage', '❌ User already exists');
            return res.redirect('/user/register');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new userSchema({
            name,
            email,
            password: hashedPassword
        });

        await newUser.save();
        req.flash('successMessage', '✅ User registration successful');
        return res.redirect('/user/login');

    } catch (err) {
        console.log(`Error during signup post: ${err}`);
        req.flash('errorMessage', '❌ Registration failed');
        return res.redirect('/user/register');
    }
};

// ========================== GOOGLE AUTH ================================
function googleRender(req, res) {
    try {
        passport.authenticate('google', { scope: ['email', 'profile'] })(req, res);
    } catch (err) {
        console.log("Error on google render ", err);
    }
}
const googleCallback = (req, res, next) => {
    try {
        passport.authenticate('google', (err, user, info) => {
            if (err) {
                console.log("Error on google auth callback", err);
            }

            if (!user) {
                return res.redirect('/user/login');
            }

            req.logIn(user, (err) => {
                if (err) {
                    return next(err); // fixed: 'arr' -> 'err'
                }
                req.session.user = user.id;
                return res.redirect('/user/home');
            });
        })(req, res, next);

    } catch (err) {
        console.log("Error on google callback ", err);
    }
};

// ========================== LOGOUT ================================
const logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(`Error during session logout`);
        } else {
            res.redirect('/user/login');
        }
    });
};

module.exports = {
    user,
    login,
    loginPost,
    register,
    registerPost,
    googleRender,
    googleCallback,
    logout,
};
