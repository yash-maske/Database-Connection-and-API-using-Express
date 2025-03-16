import UserModel from '../models/User.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import transporter from '../config/emailConfig.js'

class UserController{
    static userRegistration = async (req,res)=>{
        const {name,email,password,password_confirmation,tc} = req.body
        const user = await UserModel.findOne({email:email});
        if(user){
            res.send({"status":"failed","message":"Email Already Exists"});
        }else{
            if(name && email && password && password_confirmation && tc){
                if(password === password_confirmation){
                   
                    try{
                        const salt = await bcrypt.genSalt(10);
                        const hashPassword = await bcrypt.hash(password,salt);
                        const doc = new UserModel({
                            name : name,
                            email : email,
                            password : hashPassword,
                            tc : tc
                        })
                        await doc.save()
                        const saved_user = await UserModel.findOne({email:email})
                        
                        //Generatng JWT

                        const token = jwt.sign({userID:saved_user._id},process.env.JWT_SECRET_KEY,{expiresIn:'5d'})

                        res.status(201).send({"status":"success","message":"Registerd Successfully","token":token});
                    }catch(error){
                        res.send({"status":"failed","message":error});
                    }
                }else{
                    res.send({"status":"failed","message":"Password and Confirm Paaword doesn't match"});
                }
            }else{
                res.send({"status":"failed","message":"All Fields are required"});
            }
        }
    }

    static userLogin = async (req,res) =>{
        try{
            const {email,password} = req.body
            if(email && password){
            const user =await UserModel.findOne({email:email});
            if(user != null){
                const isMatch = await bcrypt.compare(password,user.password)
                
                if((user.email===email) && isMatch){
                    
                    const token = jwt.sign({userID:user._id},process.env.JWT_SECRET_KEY,{expiresIn:'5d'})
                    res.send({"status":"success","message":"Login Successful","token":token});
                }else{
                    res.send({"status":"failed","message":"Incorrect Credentials"});
                }
            }else{
                res.send({"status":"failed","message":"Enterd email is not registerd please sign up first"});
            }
            }else{
                res.send({"status":"failed","message":"All Fields are required"});
            }
        }catch(error){
            res.send({"status":"failed","message":error});
        }
    }

    static changeUserPassword = async(req,res)=>{
        const {password,password_confirmation} = req.body
        if(password && password_confirmation){
            if(password===password_confirmation){
                const salt = await bcrypt.genSalt(10)
                const NewhashPassword = await bcrypt.hash(password,salt);
                // console.log(req.user)
                await UserModel.findByIdAndUpdate(req.user._id,{$set:{password:NewhashPassword}})

                res.send({"status":"success","message":"Password Chnaged Succesfully"});

            }else{
                res.send({"status":"failed","message":"Password and Confirm Password doesn't match"});
            }
        }else{
            res.send({"status":"failed","message":"All Fields are required"});
        }
    }

    static loggedUser = async (req,res)=>{
        res.send({"user":req.user})
    }

    static sendUserPasswordResetEmail = async(req,res) =>{
        const {email} = req.body
        if(email){
            const user = await UserModel.findOne({email:email});
            
            if(!user){
                res.send({"status":"failed","message":"Invalid Email Address"});
            }else{
                const secret = user._id + process.env.JWT_SECRET_KEY
                const token = jwt.sign({userID:user._id},secret,{expiresIn:'15m'})
                const link = `http://localhost:3000/api/user/reset-password/${user._id}/${token}`
                


                let info = await transporter.sendMail({
                    from:process.env.EMAIL_FROM,
                    to:user.email,
                    subject : "Auth Learner Password Reset Link",
                    html :`<a href=${link}>Click Here to Reset Your Password</a>`
                })
                res.send({"status":"success","message":"Reset Password Link is Successfuly sent to your registered email id","info":info});
            }
        }else{
            res.send({"status":"failed","message":"Please Enter Email ID"});
        }
        
    }

    static userPasswordReset = async(req,res)=>{
        const {password,password_confirmation} = req.body
        const {id,token} = req.params
if(password&&password_confirmation){
    if(password === password_confirmation){

        const  user = await UserModel.findById(id)
        if(user){
            const new_secret = user._id + process.env.JWT_SECRET_KEY

            try{
                jwt.verify(token,new_secret);
                const salt = await bcrypt.genSalt(10)
                const NewhashPassword = await bcrypt.hash(password,salt)

                await UserModel.findByIdAndUpdate(user._id,{$set:{password:NewhashPassword}})

                res.send({"status":"success","message":"Password reset successfully"})
                
            }catch(error){
                res.send({"status":"failed","message":"Token id Not Valid"});
            }
        }else{
            res.send({"status":"failed","message":"Invalid User"});
        }
        
    }else{
        res.send({"status":"failed","message":"Password and Confirm Password doesn't match"});
    }
}else{
    res.send({"status":"failed","message":"All Fields are required"});
}
        
    }
}

export default UserController