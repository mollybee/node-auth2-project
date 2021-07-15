const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken'); //Here we're acquiring our token
const User = require("../users/users-model"); //Importing our model

//Here we're creating our 'restricted' authorization 
/*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
const restricted = (req, res, next) => {
  const token = req.headers.authorization; //where our token lives
  if(!token){
    res.status(401).json({message:"Token required"});
  } else {
      jwt.verify(token, JWT_SECRET, (err, decoded) => {  //Testing the passed in token with the JWT token we've imported
          if(err) {
            res.status(401).json("Token invalid");
          } else {
             req.decodedToken = decoded; //LINE 19
             next();
          }
      })
  }
}
/**~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
const only = role_name => (req, res, next) => {
  if(decoded.role_name !== role_name) { //comparing the token's role name to the role name passed in
    res.status(403).json({message: "This is not for you"});
  } 
}

/**~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
const checkUsernameExists = (req, res, next) => {
  console.log("In the checkUsernameExists")
  const username = req.body.username;

  User.findBy({username}) 
  .then((user) => {
    console.log("In the user.findby callback.then")

      if (user) {
        next();

      } else {
        res.status(401).json({
          message: "Invalid credentials"
        });
      }

  })
  .catch((err) => {  
    console.log("In the user.findby callback.catch")
    res.status(500).json(err);
  });

}


/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
const validateRoleName = (req, res, next) => {
  const trimmedRoleName = req.body.role_name?.trim(); // trim the role_name white space
    const roleName = trimmedRoleName || "student"; // ?.trim() the question mark is 'optional chaining' in JS, to avoid continuing evaluation the expression and just returning 'undefined', if what i'm accessing is null

    if (roleName === "admin") {
      res.status(422).json({  message: "Role name can not be admin" });
    } else if (trimmedRoleName.length > 32) { //Because we're testing the # of characters
      res.status(422).json({
        message: "Role name can not be longer than 32 chars"
      });
    } else {
      req.role_name = trimmedRoleName;
      next();
    };      

}



module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
