const express=require('express')
const admin=express.Router()
const adminSection=require('../middleware/adminSection')
const loginController=require('../controller/adminController/loginContoller')
const dashboardController=require('../controller/adminController/dashboardController')



admin.get('/',loginController.admin)
admin.get('/login',loginController.login)
admin.post('/login',loginController.loginPost)


admin.get('/dashboard',adminSection,dashboardController.dashboard)

admin.get('/edit-user/:id',adminSection,dashboardController.editUser)
admin.post('/edit-user/:id',adminSection,dashboardController.editUserPost)
admin.get('/delete-user/:id',dashboardController.deleteUser)
admin.get('/add-user',adminSection,dashboardController.addUser)
admin.post('/add-user',dashboardController.addUserPost)


admin.get('/logout',loginController.logout)

module.exports=admin