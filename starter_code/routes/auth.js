const express = require("express");
const bcrypt = require("bcrypt");

const User = require("../models/user");

const router = express.Router();
const bcryptSalt = 10;

router.get("/signup", (req, res, next) => {
  res.render("auth/signup", {
    errorMessage: ""
  });
});

router.post("/signup", (req, res, next) => {
  const nameInput = req.body.name;
  const usernameInput = req.body.username;
  const emailInput = req.body.email;
  const passwordInput = req.body.password;

  if (emailInput === "" || passwordInput === "" || usernameInput === "") {
    res.render("auth/signup", {
      errorMessage: "Please fill all fields."
    });
    return;
  }

  User.findOne({ email: emailInput }, "_id", (err, existingUser) => {
    if (err) {
      next(err);
      return;
    }

    if (existingUser !== null) {
      res.render("auth/signup", {
        errorMessage: `The email ${emailInput} is already in use.`
      });
      return;
    }
    User.findOne({ username: usernameInput }, "_id", (err, existingUser) => {
        if (err) {
          next(err);
          return;
        }
    
        if (existingUser !== null) {
          res.render("auth/signup", {
            errorMessage: `The username ${usernameInput} is already in use.`
          });
          return;
        }
    });
    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashedPass = bcrypt.hashSync(passwordInput, salt);

    const userSubmission = {
      name: nameInput,
      username: usernameInput,
      email: emailInput,
      password: hashedPass
    };

    const theUser = new User(userSubmission);

    theUser.save(err => {
      if (err) {
        res.render("auth/signup", {
          errorMessage: "Something went wrong. Try again later."
        });
        return;
      }

      res.redirect("/");
    });
  });
});

router.get("/login", (req, res, next) => {
  res.render("auth/login", {
    errorMessage: ""
  });
});

router.post("/login", (req, res, next) => {
  const credentials = req.body.credentials;
  const passwordInput = req.body.password;

  if (credentials === "" || passwordInput === "") {
    res.render("auth/login", {
      errorMessage: "Enter email/username and password to log in."
    });
    return;
  }

  User.findOne({$or: [{email: credentials},{username: credentials}]}, (err, theUser) => {
    if (err || theUser === null) {
      res.render("auth/login", {
        errorMessage: `Invalid Email/Username or Password.`
      });
      return;
    }

    if (!bcrypt.compareSync(passwordInput, theUser.password)) {
      res.render("auth/login", {
        errorMessage: "Invalid Email/Username or Password."
      });
      return;
    }
    req.session.currentUser = theUser;
    res.redirect("/");
  });
});

router.get("/logout", (req, res, next) => {
  if (!req.session.currentUser) {
    res.redirect("/");
    return;
  }

  req.session.destroy(err => {
    if (err) {
      next(err);
      return;
    }

    res.redirect("/");
  });
});

module.exports = router;