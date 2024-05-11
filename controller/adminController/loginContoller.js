const dotenv=require('dotenv').config()


const admin=(req,res)=>{
    try {
       if(req.session.admin){
        res.redirect('/admin/dashboard')
       }else{
        res.redirect('/admin/login')
       }
        
    } catch (err) {
        console.log(`Error redirect to admin login`);
    }
}




const login=(req,res)=>{
    try{
        if(req.session.admin){
            res.redirect('/admin/dashboard')
        }else{
            res.render('admin/login',{title:"ADMIN login",alertMessage:req.flash('errorMessage')})
        }
    }catch(err){
        console.log(`Error during admin login page render ${err}`);
    }
}


const loginPost = (req, res) => {
    try {

        if(req.body.email===process.env.ADMIN_USERNAME && req.body.password===process.env.ADMIN_PASSWORD){
            req.session.admin=req.body.email
            res.redirect('/admin/dashboard')
        }else{
            req.flash("errorMessage",'Invalid username or password')
            res.redirect('/admin/login')
        }

    } catch (err) {
        console.log(`Error during admin login ${err}`);
    }
}


const logout=(req,res)=>{
    try {
        req.session.destroy((err)=>{
            if(err){
                console.log(`Error during session destroy in admin ${err}`);
            }else{
                res.redirect('/admin/login')
            }
        })
        
    } catch (err) {
        console.log(`Error while admin logout ${err}`);
    }
}

module.exports = {
    admin,
    login,
    loginPost,
    logout
}