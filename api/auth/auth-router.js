const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcrypt'); //for hashing 
const jwt = require('jsonwebtoken');

const Users = require("../users/users-model.js");
const { default: jwtDecode } = require("jwt-decode");


  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  user.role_name = req.role_name;
  //gaining access to the object we need
  const rounds = process.env.BCRYPT_ROUNDS || 12; //Salting - to create random and more time to avoid brute-force hacking
  const hash = bcrypt.hashSync(user.password, rounds); //creating the hashed password with the salt created above

  user.password = hash; //saving the users password to the database
  //Below: Save the user (for a sesssion?)
  Users.add(user)
    .then(saved => { res.status(201).json({message: `Welcome, ${saved.username}`})
    })
    .catch(next()); //the middleware handles the errors, therefore you don't need to do so here
});

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/ 

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
router.post("/login", checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;
  Users.findBy({username})
    .then(([user]) => {
      console.log("user:", user);
      if(user && bcrypt.compareSync(password, user.password)) { //If the users password credentials match the database, we generate a token
        //creating our token here
        const token = makeToken(user);
        console.log(jwtDecode(token)); //here we're decoding the token and sending it back to the client from the server?
        res.status(200).json({message: `${user.username} is back`, token});
      } else {
        res.status(401).json({message: "Invalid credentials"});
      }
    })
    .catch(next());
});

//Below we create our makeToken function that these endpoints can access
function makeToken(user){
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const options = {
    expiresIn: "500s"
  }
  console.log("make token: ", jwt.sign(payload,JWT_SECRET, options))
  return jwt.sign(payload, JWT_SECRET, options) //We will also be creating a token using JWT. We use jwt.sign() and pass in first the user data and that token secret we hid in our .env file.
};

module.exports = router;
