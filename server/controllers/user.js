import { User } from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sendMail from "../middlewares/sendMail.js";
import TryCatch from "../middlewares/TryCatch.js";

export const register=async(req,res)=>{
    try{
        const {email,name,password}=req.body;

        let user=await User.findOne({email});

        if(user){
            return res.status(400).json({message:"User already exists",});
        }
        const hashpassword=await bcrypt.hash(password,10);
          user={
                name,
                email,
                password:hashpassword,
          }
          const otp=Math.floor(Math.random()*1000000);

          const activationToken=jwt.sign({
            user,
            otp,
          },process.env.Activation_secret,{
            expiresIn:"10m"
        });

        const data={
            name,
            otp,
        }
        await sendMail(
            email,
            "Account Activation",
            data
        )
        res.status(200).json({message:"OTP has been sent",activationToken});
    }
    catch(error){
        res.status(500).json({message:error.message})
    }
};

export const verifyUser=TryCatch(async(req,res)=>{
    const {otp,activationToken}=req.body;

    const verify=jwt.verify(activationToken,process.env.Activation_secret); 

    if(!verify){
        return res.status(400).json({message:"Invalid or expired OTP"});
    }

    if(verify.otp!==otp){
        return res.status(400).json({message:"Invalid OTP"});
    }

    await User.create({
        name:verify.user.name,
        email:verify.user.email,
        password:verify.user.password,
    })
    res.status(201).json({message:"User registered successfully"});
});

export const login=TryCatch(async(req,res)=>{
    const {email,password}=req.body;

    const user=await User.findOne({email});
    if(!user){
        return res.status(400).json({message:"User does not exist"});
    }
    const mathPassword=await bcrypt.compare(password,user.password);

    if(!mathPassword){
        return res.status(400).json({message:"Invalid credentials"});
    }

    const token=jwt.sign({id:user._id},process.env.JWT_SEC,{
        expiresIn:"15d",
    });
    res.json({
        message:`${user.name} logged in successfully`,
        token,
        user,
    })
});