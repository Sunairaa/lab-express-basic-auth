const { Router } = require('express');
const router = new Router();

// require bcrypt and salt rounds to initialize
const bcrypt = require('bcryptjs');
const saltRounds = 10;

// require auth middleware
// const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

// require user model
const User = require('../models/User.model');

// require auth middleware
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

// GET route ==> to display the signup form to users
router.get('/signup', isLoggedOut, (req, res) => res.render('auth/signup'))

// POST route ==> to process form data
router.post('/signup', isLoggedOut, (req, res, next) => {
    const { username, password } = req.body;
   
    // encrypt password
    bcrypt
      .genSalt(saltRounds)
      .then(salt => bcrypt.hash(password, salt))
      .then(hashedPassword => {
        return User.create({
          username,
          password: hashedPassword
        });
      })
      .then(userFromDB => {
        console.log('Newly created user is: ', userFromDB);
        // req.session.currentUser = userFromDB;
        // res.redirect('/auth/userProfile')
        res.redirect('/auth/login')
      })
      .catch(error => next(error));
  });

//GET route ==> route for user profile
router.get('/userProfile', isLoggedIn, (req, res) => {
    const { username } = req.session.currentUser;
    res.render('users/user-profile', {username});
});

//////////// L O G I N ///////////
 
// GET route ==> to display the login form to users
router.get('/login', isLoggedOut, (req, res) => res.render('auth/login'));

// POST login route ==> to process login form data
router.post('/login', isLoggedOut, (req, res, next) => {
  console.log('SESSION =====> ', req.session);
  const { username, password } = req.body;
 
  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, username and password to login.'
    });
    return;
  }
 
  User.findOne({ username })
    .then(user => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'User is not registered. Try with other username.' });
        return;
      } else if (bcrypt.compareSync(password, user.password)) {
        //******* SAVE THE USER IN THE SESSION ********//
        req.session.currentUser = user;
        res.redirect('/auth/userProfile');
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
});

// POST login route ==> to destory session
router.post('/logout', isLoggedIn, (req, res, next) => {
  // res.clearCookie(connect.sid);
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});

// Get route to go main page
router.get('/main', isLoggedIn, (req, res) => {
  const { username } = req.session.currentUser;
  res.render('users/main', { username });
})


// Get route to go private page
router.get('/private', isLoggedIn, (req, res) => {
  const { username } = req.session.currentUser;
  res.render('users/private', { username });
})

module.exports = router;
