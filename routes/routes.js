const {Router} = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const router = Router();

router.post('/register',async(req,res)=>{

    const {name,email,password} = req.body;

    const salt = await bcrypt.genSalt(10);
    const hashPass = await bcrypt.hash(password,salt);

    const record = await User.findOne({email:email});

    if(record){
        return res.status(400).send({
            message: "Email is already registered"
        })
    } else{
        const user = new User({
            name,
            email,
            password: hashPass
        })
        const result = await user.save();

        //  jwt Token
        const {_id} = result.toJSON()
        const token = jwt.sign({_id:_id},"secret")

        res.cookie("jwt",token,{
            httpOnly: true,
            maxAge: 24*60*60*1000
        })
       res.send({
        message: "success"
       })
    }
});   


router.post('/login',async(req,res)=>{
    const user = await User.findOne({ email: req.body.email });
    if(!user){
        return res.status(404).send({
            message:"User not found"
        })
    }

    const matchPass = await bcrypt.compare(req.body.password , user.password);
    if(!matchPass){
        return res.status(400).send({
            message:"Password is incorrect"
        })
    }


    const token = jwt.sign({_id:user._id},"secret");
    res.cookie("jwt",token,{
        httpOnly:true,
        maxAge:24*60*60*1000
    })
    res.send({
        message:"success"
    })

})


router.get('/user',async(req,res)=>{
    try {
        const cookie = req.cookies['jwt']
        const claims= jwt.verify(cookie,'secret')

        if(!claims){
            return res.status(401).send({
                message:"unauthenticated"
            })
        }

        const user = await User.findOne({ _id: claims._id });
        const {password,...data}= await user.toJSON();

        res.send(data)
    } catch (error) {
        return res.status(401).send({
            message: "unauthenticated"
        })
    }
})

router.post('/logout',async(req,res)=>{
    res.cookie("jwt","",{maxAge:0})

    res.send({
        message:"success"
    })
})

module.exports  = router;