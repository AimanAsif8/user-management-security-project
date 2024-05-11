const userSchema = require("../../model/userSchema");
const bcrypt=require('bcrypt')



const dashboard = async (req, res) => {
    try {

        // user search 
        const userSearch = req.query.search || '';

        const userDetails = await userSchema.find({ name: { $regex: userSearch, $options: 'i' } })

        if (userDetails.length === 0) {
            req.flash('errorMessage', 'No user registration details is available')
        }

        res.render('admin/dashboard', { title: "Dashboard", alertMessage: req.flash('errorMessage'), userDetails })
    } catch (err) {
        console.log(`Error rendering dashboard ${err}`);
    }
}


const editUser = async (req, res) => {
    try {
        const userID = req.params.id;
        const userData = await userSchema.findById(userID)
        res.render('admin/editUser', { title: "Edit user", alertMessage: req.flash('errorMessage'), userData })

    } catch (err) {
        console.log(`Error during user editing ${err}`);
    }
}


const editUserPost = async (req, res) => {
    try {

        const userID = req.params.id;
        const updateStatus = await userSchema.findByIdAndUpdate(userID, { name: req.body.editName })
        if (updateStatus === undefined) {
            req.flash("errorMessage", 'User data not updated please try again')
            return res.redirect('/admin/dashboard')
        }
        req.flash("errorMessage", 'User data updated')
        res.redirect('/admin/dashboard')

    } catch (err) {
        console.log(`Error during user data updation ${err}`);
    }
}

const addUser=(req,res)=>{
    try {
        res.render('admin/addUser',{title:"Add user",alertMessage:req.flash('errorMessage')})
    } catch (err) {
        console.log(`Error rendering add user page ${err}`);
    }
}

const addUserPost=async (req,res)=>{
    try{
        const userData = {
            name: req.body.name,
            email: req.body.email,
            password: await bcrypt.hash(req.body.password,10),
        }

        const checkUserExist = await userSchema.find({ email: req.body.email })

        if (checkUserExist.length === 0) {

            userSchema.insertMany(userData).then((result) => {
                req.flash('errorMessage',"User Registration is successful")
                return res.redirect('/admin/dashboard')
            }).catch((err) => {
                console.log(`Error while inserting new user ${err}`);
            })
        } else {
           req.flash('errorMessage','User already exist')
           return res.redirect('/admin/dashboard')
        }

    }catch(err){
        console.log(`Error while adding user ${err}`);
    }
}




const deleteUser=async(req,res)=>{
    try {

        const userID=req.params.id;
        const deleteStatus=await userSchema.findByIdAndDelete(userID)
        if(deleteStatus===undefined){
            req.flash("errorMessage",'User data cannot delete at the moment please try again')
            res.redirect('/admin/dashboard')
        }else{
            req.flash("errorMessage",'user deleted')
            res.redirect('/admin/dashboard')
        }
        
    } catch (err) {
        console.log(`Error during user data delete ${err}`);
    }
}




module.exports = {
    dashboard,
    editUser,
    editUserPost,
    deleteUser,
    addUser,
    addUserPost
}