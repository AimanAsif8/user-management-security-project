const express=require('express')
const userSchema = require('../model/userSchema')
const user=express.Router()

const userLoginControl=require('../controller/userController/loginController')
const userHomeControl=require('../controller/userController/homeController')

const userSection=require('../middleware/userSection')

user.get('/',userLoginControl.user)
user.get('/login',userLoginControl.login)

user.post('/login',userLoginControl.loginPost)

user.get('/register',userLoginControl.register)

user.post('/register',userLoginControl.registerPost)

user.get('/home',userSection, userHomeControl.home)

user.get('/logout',userLoginControl.logout)

module.exports=user