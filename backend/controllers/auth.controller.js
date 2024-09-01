import { User } from '../models/user.model.js';
import bcryptjs from "bcryptjs";
import { generateTokenAndSetCookie } from '../utils/generateToken.js';

export async function signup(req, res){
    try {
        const {email, password, username} = req.body;

        if(!email || !password || !username) {
            return res.status(400).json({success:false,message:"Please make sure to fill out EVERY field."})
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if(!emailRegex.test(email)){
            return res.status(400).json({success:false,message:"Please put in a valid email"})
        }

        if(password.length < 6){
            return res.status(400).json({success:false,message:"Please make sure your password is at least 6 characters"})
        }

        const existingUserbyEmail = await User.findOne({email:email})

        if(existingUserbyEmail){
            return res.status(400).json({success:false,message:"Email already exists, please try again."})
        }

        const existingUserbyUsername = await User.findOne({username:username})

        if(existingUserbyUsername){
            return res.status(400).json({success:false,message:"Username already exists, please try again."})
        }

        const salt = await bcryptjs.genSalt(10);
        const hashedPassword = await bcryptjs.hash(password, salt);

        const PROFILE_PICS = ["/avatar1.png", "/avatar3.png", "/avatar3.png"];
        const image = PROFILE_PICS[Math.floor(Math.random() * PROFILE_PICS.length)];

        const newUser = new User({
            email,
            password: hashedPassword,
            username,
            image
        });

        
        generateTokenAndSetCookie(newUser._id, res);
        await newUser.save();
        // Removes password from response
        res.status(201).json({ success: true, user: {
            ...newUser._doc,
            password:""
        }})
        

        

        

    } catch (error) {
        console.log("Error in signup controller",error.message);
        res.status(500).json({success:false,message:"Internal server error. Sorry about that!"});
    }
}

export async function login(req, res){
    try {
        const {email, password} = req.body;
        
        if(!email || !password) {
            return res.status(400).json({success: false, message: "All fields are required, please try again."});
        }

        const user = await User.findOne({email: email});
        if(!user) {
            return res.status(404).json({success: false, message: "Invalid credentials, please try again."});
        }

        const isPasswordCorrect = await bcryptjs.compare(password, user.password);

        if(!isPasswordCorrect) {
            return res.status(400).json({success: false, message: "Incorrect password, please try again."});
        }

        generateTokenAndSetCookie(user._id, res);

        res.status(200).json({
            success: true,
            user: {
                ...user._doc,
                password: ""
            }
        });


    } catch (error) {
        console.log("Error in logout controller", error.message);
        res.status(500).json({success:false,message:"Internal server error. Sorry about that!"});
    }
}

export async function logout(req, res){
    try {
        res.clearCookie("jwt-netflix");
        res.status(200).json({success: true, message: "Logged out successfully. Have a good day!"})
    } catch (error) {
        console.log("Error in logout controller", error.message);
        res.status(500).json({success:false,message:"Internal server error. Sorry about that!"});
    }
}

export async function authCheck(req, res) {
	try {
		console.log("req.user:", req.user);
		res.status(200).json({ success: true, user: req.user });
	} catch (error) {
		console.log("Error in authCheck controller", error.message);
		res.status(500).json({ success: false, message: "Internal server error" });
	}
}