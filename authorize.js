const express = require('express');
const router = express.Router();
const authHelp = require('../helpers/auth.js');
const appLog = require('../utilities/appLogging');

/* GET /authorize. */
router.get('/', async function(req, res) {
    
    if (req.query.code !== undefined) {

        appLog(`authorize: ${req.originalUrl}`);

        const redirectUrl = req.query.state;
        
        authHelp.getTokenFromCode(req.query.code, function (e, access_token, refresh_token, results) {
            if (e === null) {

                const config = {
                    AL_APP_URL: process.env.AL_APP_URL,
                    ENVNAME: process.env.ENVNAME,
                    AOA_UI_API_URL: process.env.AOA_UI_API_URL
                };

                res.cookie('MS_TOKEN', access_token, {maxAge: (results.expires_in * 1000)});
                res.cookie('AOAREDIRECT', redirectUrl, {maxAge: 30000});
                res.cookie('APP_CONFIG', JSON.stringify(config), {maxAge: (results.expires_in * 1000)});


                if (redirectUrl) {
                    appLog(`authorize: /amwinsAuth?redirect=${encodeURIComponent(redirectUrl)}`);
                    res.redirect(`/amwinsAuth?redirect=${encodeURIComponent(redirectUrl)}`);
                } else {
                    res.send('Error in authorize: No page redirect cookie was found');
                }

                res.end();

            } else {
                appLog(JSON.parse(e.data).error_description);
                res.status(500);
                res.redirect('/errors?errorMsg=' + encodeURIComponent(JSON.parse(e.data).error_description));
                res.send(JSON.parse(e.data).error_description);
                res.end();
            }
        });

    } else {
        
        if (!req.query.redirect) {
            res.redirect('/errors?errorMsg=' + encodeURIComponent('authorize.js Error: No redirect Query parameter specified!!!!  Cannot complete Authorization'));
            return;
        }
        appLog(`authorize  ==> req.query.redirect === : ${req.query.redirect}`);
        res.cookie('AOAREDIRECT', req.query.redirect, {maxAge: 30000});
        appLog(`authorize: ${authHelp.getAuthUrl()}&state=${encodeURIComponent(req.query.redirect)}`);
        res.set({
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Expires': '-1'
        });
        res.redirect(`${authHelp.getAuthUrl()}&state=${encodeURIComponent(req.query.redirect)}`);
    }
});

router.get('/renew', async function (req, res) {
    res.clearCookie('MS_TOKEN');
    res.clearCookie('REFRESH_TOKEN_CACHE_KEY');
    res.cookie('IS_RENEW', 'true', {maxAge: 30000});
    res.redirect(authHelp.getAuthUrl());
});

module.exports = router;