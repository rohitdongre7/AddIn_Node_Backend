const config = require("../config/config");
const jwt = require('jsonwebtoken');
const OAuth = require('oauth');
const axios = require("axios");
const expect = require("chai").expect;
const randomstring = require("randomstring");
const crypto = require("crypto");
const subtle = require("webcrypto-core");
const base64url = require("base64url");
const base64encode = require("base64-arraybuffer").encode;
const { Crypto } = require("webcrypto-core");
const { AuthorizationCode } = require('simple-oauth2');
const fetch = require('node-fetch');
const request = require('superagent');

const state = randomstring.generate();
const code_verifier = randomstring.generate(128);

const base64Digest = crypto
  .createHash("sha256")
  .update(code_verifier)
  .digest("base64");

const code_challenge = base64url.fromBase64(base64Digest);

exports.getLoginUrl = (req, res) => {
    var challenge = generateCodeChallenge(code_verifier);
    var uri = buildLoginUrl(challenge);
    //res.json( { items : uri } );
    res.status(200).json({message : uri})
}

exports.getAmlinkAuth = (req, res) => {
    // generateCodeChallenge(code_verifier).then((challenge) => {
    //     buildLoginUrl(challenge);
    // });

    var challenge = generateCodeChallenge(code_verifier);
    var uri = buildLoginUrl(challenge);

    // axios.get(uri)
    // .then(response => {
    //     console.log(response.data.url);
    //     console.log(response.data.explanation);
    // })
    // .catch(error => {
    //     console.log(error);
    // });
    
    res.redirect(uri);
    res.end();
    // axios({
    //     method: "GET",
    //     "url": uri //"http://localhost:3000/api/getAmlinkAuth/"
    // }).then(response => {
    //     var tokenData = response.data;
    //     console.log(tokenData);
    // }, error => {
    //     // eslint-disable-next-line
    //     console.error(error);
    // });
}

function generateCodeChallenge(codeVerifier) {
    // const encoder = new TextEncoder();
    // const data = encoder.encode(codeVerifier); 
    
    // const subtle1 = new Crypto();
    // const digest = subtle1.digest('SHA-256', data);
    // const base64Digest = base64encode(digest);
    // // you can extract this replacing code to a function

    const base64Digest = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64");

    const code_challenge = base64url.fromBase64(base64Digest);
    return code_challenge
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
}

function buildLoginUrl(challenge) {
    // const link = document.querySelector("a");
    // const linkValue = new URL("https://identitydev.amwins.com/connect/authorize");
  
    // const queryParams = {      
    //   client_id: 'amlink-outlook-addin',
    //   //client_secret: '21c3d5637e454034b4af700790843153',
    //   response_type: 'code',
    //   state: state,
    //   code_challenge: challenge,
    //   code_challenge_method: "S256",
    //   redirect_uri: 'http://localhost:3000/api/callback'
    // };
  
    return "https://identitydev.amwins.com/connect/authorize" + 
            '?response_type=' + 'code' + 
            '&client_id=' + 'amlink-outlook-addin' + 
            '&redirect_uri=' + 'http://localhost:3000/api/callback' + 
            '&state=' + state +
            '&code_challenge=' + challenge + 
            '&code_challenge_method=' + 'S256' + 
            '&scope=' + 'amlink-doc-api amlink-submission-api';

                            //'&scope=' + 'amlink-doc-api amlink-submission-api';
}

const credentials = {
    authorityHostUrl: process.env.AUTHORITYHOSTURL,
    authEndPoint: process.env.AUTHORIZEENDPOINT,
    tokenEndPoint: process.env.TOKENENDPOINT,
    logout_endpoint: process.env.LOGOUTENDPOINT,
    tenant: process.env.TENANT,
    authorityUrl: process.env.AUTHORITYHOSTURL + '/' + process.env.TENANT,
    clientId: process.env.CLIENTID,
    clientSecret: process.env.CLIENTSECRET,
    redirectUri: process.env.AUTHREDIRECTURL,
    resource: process.env.GRAPHAPIURI
};

const templateAuthUrl = credentials.authorityUrl 
                      + credentials.authEndPoint 
                      + '?response_type=code&client_id=' 
                      + credentials.clientId 
                      + '&redirect_uri=<URI>&mobileredirect=true&resource=' 
                      + credentials.resource;

let templateAuthUrl1 = "https://identitydev.amwins.com/connect" + 
'/authorize?response_type=code&client_id=' +
"amlink-outlook-addin" + 
'&redirect_uri=' + 
'http://localhost:3000/api/callback' + 
'&response_mode=query&state=<state>' + 
'&scope=' + 'amlink-doc-api amlink-submission-api';
  
function createAuthorizationUrl(state) {
  return templateAuthUrl1.replace('<state>', state);
}

exports.ruthAuth = (req, res) => {    
    // const authorizationUrl = templateAuthUrl1; //createAuthorizationUrl(encodeURIComponent(req.query.redirect));
  
    // res.set({
    //     'Pragma': 'no-cache',
    //     'Cache-Control': 'no-cache',
    //     'Expires': '-1'
    // });
    // res.redirect(authorizationUrl);    

    getTokenFromCode('code', function (e, access_token, refresh_token, results) {
        if (e === null) {

            const config = {
                AL_API_URL: process.env.AL_API_URL,
                AOA_API_URL: process.env.AOA_API_URL,
                AOA_UI_API_URL: process.env.AOA_UI_API_URL,
                API_KEY: process.env.API_KEY,
                APP_LOGGING_LOG_TO_CONSOLE: process.env.APP_LOGGING_LOG_TO_CONSOLE,
                AL_APP_URL: process.env.AL_APP_URL,
                ENVNAME: process.env.ENVNAME
            };

            res.cookie('APP_CONFIG', JSON.stringify(config), {maxAge: (results.expires_in * 1000)});
            res.cookie('AW_TOKEN', access_token, {maxAge: (results.expires_in * 1000)});

            if (redirectUrl) {    
                appLog(`amwinsAuth ===> getAToken() ==> redirectUrl === ${redirectUrl}`);
                res.redirect(redirectUrl);
            } else {
                res.send('Error in amwinsAuth.js ===> getAToken(): No page redirect query parameter was found');
            }
        } else {            
            // appLog('amwinsAuth: An error has occurred:');
            // appLog('');
            // appLog('amwinsAuth: Error: ' + JSON.stringify(e));
            res.status(500);
            res.send(e);
        }
    
    });
}

function getTokenFromCode(code, callback) {
    var OAuth2 = OAuth.OAuth2;
    var oauth2 = new OAuth2(
        'amlink-outlook-addin',
        '21c3d5637e454034b4af700790843153',
        'https://identitydev.amwins.com/connect/',
        'authorize',
        'token'
    );

    oauth2.getOAuthAccessToken(
        code,
        {
            grant_type: 'authorization_code',
            redirect_uri: 'http://localhost:3000/api/callback',
            resource: 'https://identitydev.amwins.com/connect/',
            code_verifier: code_verifier
        },
        function (e, access_token, refresh_token, results) {
            callback(e, access_token, refresh_token, results);
        }
    );
}

exports.callback = async (req, res) => {     
    getTokenFromCode(req.query.code, function (e, access_token, refresh_token, results) {
        var at = access_token;
        var eee = e;
        var rt = refresh_token;
        var r = results;  
        
        const config = {            
            AL_APP_URL: "http://localhost:3001/app/",
            ENVNAME: "DEV"
        };
        
        res.cookie('APP_CONFIG', JSON.stringify(config), {maxAge: (10000)});
        res.cookie('AW_TOKEN', access_token, {maxAge: (10000)});

        let entitlementsUrl = 'https://amlink-submission-api-full05.amwins.net/v1/submissions/4957979';
        request
        .get(entitlementsUrl)
        .set('Authorization', 'Bearer ' + access_token)
        .end((err, resp) => {
            if (err) {
                res.send(err);
            } else {
                
                let entitlements = JSON.parse(resp.text); 
                res.send(entitlements);
            }
        });

        //res.redirect("http://localhost:3002/"); 
    });
    

    // const data = {
    //     // client_id: 'amlink-outlook-addin',
    //     // //client_secret: '21c3d5637e454034b4af700790843153',
    //     // grant_type: 'client_credentials',
    //     // redirect_uri: 'http://localhost:3000/api/callback',
    //     // code: req.query.code,
    //     // code_verifier: code_verifier,
    //     // scope: ['amlink-doc-api', 'amlink-submission-api'],
    //     code: req.query.code,
    //     grant_type: "authorization_code",      
    //     client_id: "amlink-outlook-addin",  
    //     redirect_uri: encodeURIComponent("http://localhost:3000/api/callback"),
    //     code_verifier: code_verifier //,        
    //     //client_secret: '21c3d5637e454034b4af700790843153'//,
    //      //scope: ['amlink-doc-api', 'amlink-submission-api']
    // };
    
    // const response = await fetch('https://identitydev.amwins.com/connect/token', {
    // method: 'POST',
    // body: new URLSearchParams(data),
    // headers: {
    //      'Content-Type': 'application/x-www-form-urlencoded',
    //      'Authorization': 'Basic YW1saW5rLW91dGxvb2stYWRkaW46MjFjM2Q1NjM3ZTQ1NDAzNGI0YWY3MDA3OTA4NDMxNTM=',
    //      'Accept': '*/*'
    //   }
    // });

    // const json = await response.json();
    // var access_token = json.access_token;
    // res.send(access_token);
//     const fetchDiscordUserInfo = await fetch('http://discordapp.com/api/users/@me', {
//   headers: {
//     Authorization: `Bearer ${json.access_token}`,
  //});

    // const client = new AuthorizationCode({
    //     client: {
    //       id: 'amlink-outlook-addin',
    //       secret: '21c3d5637e454034b4af700790843153',
    //     },
    //     auth: {
    //       tokenHost: 'https://identitydev.amwins.com/connect',
    //       tokenPath: 'token',
    //       authorizePath: 'authorize',
    //     },
    //     options: {
    //       authorizationMethod: 'body',
    //     },
    //   });


    //   const { code } = req.query;
    //   const options = {
    //     code,
    //     redirect_uri: 'http://localhost:3000/api/callback',
    //   };

    //   try {
    //     const accessToken = client.getToken(options);
  
    //     console.log('The resulting token: ', accessToken.token);
  
    //     return res.status(200).json(accessToken.token);
    //   } catch (error) {
    //     console.error('Access Token Error', error.message);
    //     return res.status(500).json('Authentication failed');
    //   }
}



exports.oauth2_code = (req, res) => {

    // var OAuth2Strategy = require('passport-oauth2');
    // var passport = require('passport-strategy');
    // var oaut = new OAuth2Strategy({
    //         authorizationURL: 'https://identitydev.amwins.com/connect/authorize',
    //         tokenURL: 'https://identitydev.amwins.com/connect/token',
    //         clientID: 'amlink-outlook-addin',
    //         clientSecret: '21c3d5637e454034b4af700790843153',
    //         scopes: ['amlink-doc-api', 'amlink-submission-api'],   
    //         redirectUri: 'http://localhost:3000/api/callback', 
    //         state: true,
    //         pkce: true
    //     },
    //     function(accessToken, refreshToken, profile, cb) {
    //         console.log(accessToken)
    //     }
    // );
    var ClientOAuth2 = require('client-oauth2')
 
    var githubAuth = new ClientOAuth2({
      clientId: 'amlink-outlook-addin', //'amlink-mobile',//
      clientSecret: '21c3d5637e454034b4af700790843153', //'20d0a448-210a-4955-92da-92174a7d7b45',//
      state: true,
      pkce: true,
      accessTokenUri: 'https://identitydev.amwins.com/connect/token',
      authorizationUri: 'https://identitydev.amwins.com/connect/authorize',
      redirectUri: 'http://localhost:3000/api/callback', //'https://www.getpostman.com/oauth2/callback',//
      scopes: ['amlink-doc-api', 'amlink-submission-api'] //,
      //authorizationGrants: ['authorization_code'] //['credentials']//    
    });  

    var uri = githubAuth.code.getUri();

    res.redirect(uri);
}

exports.oauth2 = (req, res) => {
    var ClientOAuth2 = require('client-oauth2')
 
    var githubAuth = new ClientOAuth2({
      clientId: 'amlink-pc',
      clientSecret: 'eea28384-936b-483a-94f0-21f6e7330ce9',
      accessTokenUri: 'https://identitydev.amwins.com/connect/token',
      authorizationUri: 'https://identityqa.amwins.com/connect/authorize',
      redirectUri: 'http://localhost:3000/api/callback',
      scopes: ['amlink-doc-api', 'amlink-submission-api'],
      //authorizationGrants: ['code'],
    });
    
   // var githubAuth = new ClientOAuth2({
    //    clientId: 'abc',
    //    clientSecret: '123',
    //    accessTokenUri: 'https://github.com/login/oauth/access_token',
    //    authorizationUri: 'https://github.com/login/oauth/authorize',
     //   redirectUri: 'http://localhost:3000/api/callback',
     //   scopes: ['notifications', 'gist']
    //  })

    //var token = githubAuth.createToken('access token', 'optional refresh token', 'optional token type', { data: 'raw user data' })
 
    githubAuth.credentials.getToken()          
          .then(function (token) {
            expect(token).to.an.instanceOf(ClientOAuth2.Token)            
            expect(token.tokenType).to.equal('bearer')
   
            return res.send(token.accessToken);
          });

    
        
// Set the token TTL.
    //token.expiresIn(1234) // Seconds.
    //token.expiresIn(new Date('2022-11-08')) // Date.
    
    // Refresh the users credentials and save the new access token and info.
    //token.refresh().then(storeNewToken)   
   
    
}

exports.amlinkAuthentication = (req, res) => {   
    var OAuth2 = OAuth.OAuth2;
    var oauth2 = new OAuth2(
        req.body.clientId,
        req.body.clientSecret,
        req.body.authorityUrl,
        req.body.authEndPoint,
        req.body.tokenEndPoint,
        req.body.score
    );

    var authUrl = req.body.authorityUrl 
                + '/authorize?response_type=code&client_id=' 
                + req.body.clientId 
                + '&redirect_uri=' 
                + req.body.redirectUri 
                + '&response_mode=query&state=abc&' 
                + '&scope=' 
                + req.body.scope;
        
    res.set({
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Expires': '-1'
    });
    res.redirect(authUrl);
}

exports.verifyUserToken = (req, res, next) => {
    let token = req.headers.authorization;
    if (!token) return res.status(401).send("Access Denied / Unauthorized request");

    try {
        token = token.split(' ')[1] // Remove Bearer from string

        if (token === 'null' || !token) return res.status(401).send('Unauthorized request');

        let verifiedUser = jwt.verify(token, config.TOKEN_SECRET);   // config.TOKEN_SECRET => 'secretKey'
        if (!verifiedUser) return res.status(401).send('Unauthorized request')

        req.user = verifiedUser; // user_id & user_type_id
        next();

    } catch (error) {
        res.status(400).send("Invalid Token");
    }

}
exports.IsUser = async (req, res, next) => {
    if (req.user.user_type_id === 0) {
        next();
    }
    return res.status(401).send("Unauthorized!");   
}
exports.IsAdmin = async (req, res, next) => {
    if (req.user.user_type_id === 1) {
        next();
    }
    return res.status(401).send("Unauthorized!");

}