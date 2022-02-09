const router = require('express').Router();
const {
    amlinkAuthentication, 
    verifyUserToken, 
    IsAdmin, 
    IsUser, 
    oauth2, 
    callback,
    oauth2_code,
    ruthAuth,
    getAmlinkAuth,
    getLoginUrl
} = require("../middleware/auth");
const userController = require('../controllers/user');

// Register a new User
router.post('/register', userController.register);

// Login
router.post('/login', userController.login);

// Auth user only
router.get('/events', verifyUserToken, IsUser, userController.userEvent);

// Auth Admin only
router.get('/special', verifyUserToken, IsAdmin, userController.adminEvent);

// AmWins Auth
router.post('/amwinsAuth', amlinkAuthentication);
router.post('/amwinsAuth2', oauth2);
router.get('/oauth2Code', oauth2_code);
router.get('/ruthAuth', ruthAuth);
router.get('/callback', callback);
router.get('/getAmlinkAuth', getAmlinkAuth);
router.get('/getLoginUrl', getLoginUrl);


module.exports = router;