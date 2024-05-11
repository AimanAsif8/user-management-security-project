const home=(req,res)=>{
    try {
        res.render('user/home',{title:"Home",alertMessage:req.flash('errorMessage')})
    } catch (err) {
        console.log(`Error during home page render ${err}`);
    }
}


module.exports={
    home
}