//const AuthenticationContext = require('adal-node').AuthenticationContext;
const OAuth = require('oauth');

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

// https://login.microsoftonline.com + adf1e1f5-5c6e-450e-a168-8f4de1d6740b + /oauth2/authorize + '?response_type=code&client_id=' +
// b7b4b0c5-0ece-4f5e-bb49-c5cc959eaa5e + '&redirect_uri=' + https://aoa-dev.amwins.com/authorize + '&mobileredirect=true&resource=' + 
// https://graph.microsoft.com

const templateAuthUrl = credentials.authorityUrl + credentials.authEndPoint + '?response_type=code&client_id=' + 
                        credentials.clientId + '&redirect_uri=<URI>&mobileredirect=true&resource=' + credentials.resource;


function getTokenFromRefreshToken(refreshToken, callback) {
    var OAuth2 = OAuth.OAuth2;
    var oauth2 = new OAuth2(
        credentials.clientId,
        credentials.clientSecret,
        credentials.authorityUrl,
        credentials.authEndPoint,
        credentials.tokenEndPoint
    );

    oauth2.getOAuthAccessToken(
        refreshToken,
        {
            grant_type: 'refresh_token',
            redirect_uri: credentials.redirectUri,
            resource: credentials.resource
        },
        function (e, access_token, refresh_token, results) {
            callback(e, results);
        }
    );
}


function getAuthUrl() {
    return templateAuthUrl.replace('<URI>', encodeURIComponent(credentials.redirectUri) );
}

async function getTokenFromCode(code, callback) {
    var OAuth2 = OAuth.OAuth2;
    var oauth2 = new OAuth2(
        credentials.clientId,
        credentials.clientSecret,
        credentials.authorityUrl,
        credentials.authEndPoint,
        credentials.tokenEndPoint
    );

    oauth2.getOAuthAccessToken(
        code,
        {
            grant_type: 'authorization_code',
            redirect_uri: credentials.redirectUri,
            resource: credentials.resource
        },
        function (e, access_token, refresh_token, results) {
            callback(e, access_token, refresh_token, results);
        }
    );
}



exports.getAuthUrl = getAuthUrl;
exports.getTokenFromCode = getTokenFromCode;
exports.getTokenFromRefreshToken = getTokenFromRefreshToken;
