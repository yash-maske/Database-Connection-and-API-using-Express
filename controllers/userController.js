import UserModel from '../models/User.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

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
                        res.send({"status":"success","message":"Registerd Successfully"});
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
}

export default UserController