const express=require('express')
const app=express()
const session=require('express-session')
const dotenv=require('dotenv').config()
const expressLayouts=require('express-ejs-layouts')
const path=require('path')
const userRouter=require('./router/userRouter')
const adminRouter=require('./router/adminRouter')
const flash=require('connect-flash')
const mongodbConnection=require('./config/mongodb')
const nocache=require('nocache')
const passport=require('passport')
const cookieParser=require('cookie-parser')


// port number
const port=process.env.PORT || 3000

mongodbConnection();


// flash
app.use(flash())

// nocache
app.use(nocache())


// path setting
app.use('/images',express.static(path.join(__dirname,'public','images')))
app.use('/style',express.static(path.join(__dirname,'public','style')))
app.use(express.static(path.join(__dirname,'public')))

// body parser
app.use(express.json())
app.use(express.urlencoded({extended:true}))

// session
app.use(session({
    secret:"your secret key",
    resave:false,
    saveUninitialized:true,
}))

app.use(cookieParser())
// google auth
app.use(passport.initialize());
app.use(passport.session());

// layouts
app.use(expressLayouts);
app.set('layout','./layouts/layout')

// view engine to ejs
app.set('view engine','ejs')


// routes
app.use('/user',userRouter)
app.use('/admin',adminRouter)


// first route
app.get('/',(req,res)=>{
   res.redirect("/user/login")
})

app.use("*",(req,res)=>{
    res.render('pageNotFound',{title:"Page not found"})
})


app.listen(port,(err)=>{
    if(err){
        console.log(`Error during port listening ${err}`);
    }else{
        console.log(`Server running on http://localhost:${port}`);
    }
})