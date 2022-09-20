const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

function initialize(passport) { 
    const autheticateUser = (email, password, done) =>{
        pool.query(
            `SELECT * FROM users WHERE email= $1`,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }

                console.log(results.rows);

                if (results.rows.length > 0){
                    const user = results.rows[0];

                    bcrypt.compare(password, user.password, (err, isMatch) => { 
                        /* checks the passwords if they match or not */
                        if(err){
                            throw err;
                        }
                        
                        if ( isMatch ){
                            return done(null, user); 
                            /*null means the firs perimeter is an error, null means there are no errors. Because it's a match, we return the user.*/
                        }else{
                            return done(null, false, {message: "Password is not correct"});

                        }
                    });
                }else{
                    return done(null, false, {message: "Email is not registered"});
                }
            }
        );
    };


    passport.use(
        new LocalStrategy(
            {
                usernameField: "email",
                passwordField: "password"
            },
            autheticateUser
        )
    );

    passport.serializeUser((user, done) => done(null, user.id)); 
    /*takes the user and store the user id in the session. */

    passport.deserializeUser((id, done) => {
        pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
            if(err) {
                throw err;
            }
            return done(null, results.rows[0]);
        });
    });
}

module.exports = initialize; 