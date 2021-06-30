
require('dotenv').config();
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const app = express();
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const facebookStrategy = require('passport-facebook').Strategy;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our Little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin-abiha:user123@cluster0.lhbkv.mongodb.net/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
    email : String,
    password : String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


passport.use(new facebookStrategy({
    clientID : process.env.clientID,
    clientSecret: process.env.clientSecret,
    callbackURL : "http://localhost:3000/auth/facebook/secrets",
    // profileFields: ['id','name','email']
},
function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// console.log(md5("12345"));
// It encryts the required feilds at newUser.save(function(err)) and decrypts the required feilds at find
// userSchema.plugin(encrypt,{secret: process.env.SECRET, encryptedFields: ["password"]});



app.get("/", function(req,res){
    res.render("home");
});

app.get("/auth/facebook", 
passport.authenticate("facebook",{scope: "email"}));

app.get("/auth/facebook/secrets", 
    passport.authenticate("facebook",{failureRedirect: "/login"}),
    function(req,res){
        res.redirect("/secrets");
    });

app.get("/auth/google",
    passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });



app.get("/login", function(req,res){
    res.render("login");
});
app.get("/register", function(req,res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    // if(req.isAuthenticated()){
    //     res.render("secrets");
    // }else
    // {
    //     res.redirect("/login");
    // }
    User.find({"secret" : {$ne: null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                res.render("secrets",{usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else
    {
        res.redirect("/login");
    }
});

app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;

    console.log(req.user.id);

    User.findById(req.user.id,function(err, foundUser){
        if(err){
            console.log(err);
        }
        else
        {
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.post("/register", function(req,res){
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function(err){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login",function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(err){
                res.redirect("/secrets");
            });
        }
    });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}


app.listen(port,function(){
    console.log("Server has started successfully");
});