
const express = require("express");
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");





const initializePassport = require("./passportConfig"); // to bring the passport function here.
initializePassport(passport);

const PORT = process.env.PORT || 4000; 


//Static Files
app.use(express.static('public'))
app.use('/css', express.static(__dirname + 'public/css'));




app.set("view engine", "ejs"); // This will tell the app to use the view engine
app.use(express.urlencoded({extended: false})); // will send details from the front end to our server.


app.use(
    session({
        secret: "secret",

        resave: false,

        saveUninitialized: false
        })
); 

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.set("view engine", "ejs");


app.get ("/", (req, res) => {
//res.send("Hello");
res.render("index");
});

//middleware?

app.get ("/users/register1", (req, res) => {
    res.render("register1");
})


app.get ("/users/index", (req, res) => {
    res.render("index");
    });
    


app.get ("/users/register", checkAuthenticated, (req, res) => {
    res.render("register");
    });
    
    
app.get ("/users/login", checkAuthenticated, (req, res) => {
    res.render("login");
    });


app.get ("/users/dashboard", checkNotAuthenticated, (req, res) => {
    res.render("dashboard", {user: req.user.fname}); // example of passing a user variable for EJS.
    });


app.get("/logout", function(req, res, next) {
        req.logout(function(err) {
          if (err) { return next(err); }
          res.redirect("/users/index");
        });
      });





app.post ("/users/register", async (req, res) =>{ 
    let{ fname, lname, email, phonenum, password, password2 } = req.body;

    console.log({
        fname,
        lname,
        email,
        phonenum,
        password,
        password2,
        
    });

    let errors = [];

    if (!fname || !lname || !email || !phonenum || !password || !password2){
        errors.push({message: "Please enter all fields"});
    }

    

 //  / if (phonenum =/[^0-9]/gi){
   // //   errors.push({message: "Enter a valid phone number"});
  //  }


//   if (email.match != (/^([a-zA-Z0-9\._]+)@([a-zA-Z0-9])+.([a-z]+)(.[a-z]+)?$/)){
//       errors.push({message: "Please enter a valid e-mail address"});
//     }

    
    
    if (password.length < 8 ) { 
        errors.push ({message: "Password should be at least 8 characters" });
    } 

    if (password != password2){
        errors.push ({message: "Passwords don't match! "});
    }

    if (errors.length > 0) {
        res.render("register", { errors });
    }else{
        //Form validation has passed

        let hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        
        pool.query(
            `SELECT * FROM users WHERE email = $1 `, [email], (err, results)=>{
                if (err){ 
            throw err; 
        }
      //  console.log("reaches here"); -> Just to check if the code is working.
        console.log(results.rows);

        if(results.rows.length > 0){
            errors.push({message: "Email already registered!"});
            res.render("register", {errors});

        }else{ // will save the data into our database.
            pool.query(
                `INSERT INTO users (fname, lname, email, phonenum, password)
                    VALUES  ($1, $2, $3, $4, $5)
                    RETURNING id, password`, [fname, lname, email, phonenum, hashedPassword],
                    (err, results) => {
                        if (err){
                            throw err
                        }
                        console.log(results.rows);
                        req.flash('success_msg', "You are now registered! Please log-in");
                        res.redirect("/users/login");
                    }
            );
        }

        
                });


    }

});


app.post(
    "/users/login",
    passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true 
})
);

function checkAuthenticated(req, res, next){
    if (req.isAuthenticated()){
        return res.redirect("users/dashboard");
    }
    next();

}


function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }

    res.redirect("/users/login");
}


app.listen(PORT, ()=> {
    console.log(`Server running on port ${PORT}`);
});