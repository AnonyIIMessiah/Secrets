//jshint esversion:6
require('dotenv').config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const app = express();
const mongoose=require("mongoose");
const session=require("express-session");
var findOrCreate = require('mongoose-findorcreate')
const passport=require("passport");
const passportLocalMongoose= require("passport-local-mongoose");
var GoogleStrategy = require('passport-google-oauth20').Strategy;


// const encrypt=require("mongoose-encryption");  //for level 2secuity
// const  md5=require("md5");
//for hashing we use MD5

//level 4--Salting and hashing password with bcrypt
// const bcrypt= require("bcrypt");
// const saltRounds =10;

const userSchema= new mongoose.Schema({
  email: String,
  password: String,
  googleID: String,
  secret: String
});
console.log(process.env.SECRET);
//define seceret
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});//for level 2 secuirty



app.use(express.static('public'));
app.set('view engine',"ejs");
app.use(bodyParser.urlencoded({extended:true}));


//*************************************passport********8***************

app.use(session({
   secret: "our little secret",
  resave: false,
  Uninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=new mongoose.model("user",userSchema);

passport.use(User.createStrategy());


passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.displayName });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

////////////////////////GOOGLE AUTH//////////////////////////

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //imp after googleplus depriciation
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


mongoose.connect("mongodb://localhost:27017/userDB");

app.get("/",function(req,res){
  res.render("home");
});
//google auth page
app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

//google authorized page
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get("/login",function(req,res){
  res.render("login");
});

//submit
app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("login");
  }
})

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;

  console.log(req.user.id);
  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  })
})

app.post("/login",function(req,res){
const user= new User({
  username:req.body.username,
  password:req.body.password
});

req.login(user,function(err){
  if(err){
    console.log(err);
  }else{
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
  }
)}
})
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
})

app.get("/register",function(req,res){
  res.render("register");
});

app.post("/register",function(req,res){



  //passport


   User.register({username:req.body.username},req.body.password, function(err,user){
     if(err){
       console.log(err);
       res.redirect("/register");
     }else{
       passport.authenticate("local")(req, res, function(){
         res.redirect("/secrets");
       })
     }
   })
});

app.get("/secrets",function(req,res){
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }else{
  //   res.redirect("login");
   User.find({"secret":{$ne:null}}, function(err,foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets: foundUsers});
      }
    }
  })
});


app.listen(3000,function(req,res){
  console.log("Running on port 3000");
})
