const userSchema = require("../../model/userSchema");
const bcrypt = require('bcrypt')
const passport = require('passport')
require('../../service/auth')





const user = (req, res) => {
    try {
        res.redirect('/user/login')
    } catch (err) {
        console.log('Error During user route');
    }
}


const login = (req, res) => {
    try {
        if (req.session.user) {
            res.redirect('/user/home')
        } else {
            res.render('user/login', { title: "Login", alertMessage: req.flash('errorMessage') })
        }
    } catch (err) {
        console.log(`Error on login page render ${err}`);
    }
}

const loginPost = async (req, res) => {
    try {
        const checkUser = await userSchema.findOne({ email: req.body.email })
        if (checkUser === null) {
            req.flash('errorMessage', 'Invalid username or password')
            res.redirect('/user/login')
        } else {
            const passwordCheck = await bcrypt.compare(req.body.password, checkUser.password)

            if (passwordCheck) {
                req.session.user = req.body.email
                return res.redirect('/user/home')
            } else {
                req.flash('errorMessage', 'Invalid username or password')
                res.redirect('/user/login')
            }
        }

    } catch (err) {
        console.log(`Error on login Post ${err}`);
    }

}

const register = (req, res) => {
    try {
        if (req.session.user) {
            res.redirect('/user/home')
        } else {
            res.render('user/register', { title: "Register", alertMessage: req.flash('errorMessage') })
        }

    } catch (err) {
        console.log(`Error rendering register page ${err}`);
    }
}

const registerPost = async (req, res) => {
    try {
        const userData = {
            name: req.body.name,
            email: req.body.email,
            password: await bcrypt.hash(req.body.password, 10),
        }

        const checkUserExist = await userSchema.find({ email: req.body.email })

        if (checkUserExist.length === 0) {

            userSchema.insertMany(userData).then((result) => {
                req.flash('errorMessage', "User Registration is successful")
                return res.redirect('/user/login')
            }).catch((err) => {
                console.log(`Error while inserting new user ${err}`);
            })
        } else {
            req.flash('errorMessage', 'User already exist')
            return res.redirect('/user/login')
        }


    } catch (err) {
        console.log(`Error during signup post ${err}`);
    }
}

// google auth instance
const googleRender = (req, res) => {
    try {
        passport.authenticate('google', { scope:
            [ 'email', 'profile' ] })(req, res)

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
                return res.redirect('/user/login')
            }
            req.logIn(user, (err) => {
                if (err) {
                    return next(arr)
                }
                req.session.user = user.id;
                return res.redirect('/user/home')
            })
        })(req, res, next)

    } catch (err) {
        console.log("Error on google callback ", err);
    }
}


const logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(`Error during session logout`);
        } else {
            res.redirect('/user/login')
        }
    })
}


module.exports = {
    user,
    login,
    loginPost,
    register,
    registerPost,
    googleRender,
    googleCallback,
    logout,
}