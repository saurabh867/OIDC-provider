// Load required packages
var oauth2orize = require('oauth2orize')
var User = require('../models/user');
var Client = require('../models/client');
var Token = require('../models/token');
var Code = require('../models/code');
var oauth2orize_ext = require('oauth2orize-openid');
// Create OAuth 2.0 server
var server = oauth2orize.createServer();
var server1 = oauth2orize.createServer();
var jwt = require('jwt-simple');
var jwtDecode = require('jwt-decode');
// Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

server.serializeClient(function(client, callback) {
  return callback(null, client._id);
});

server.deserializeClient(function(id, callback) {
  Client.findOne({ _id: id }, function (err, client) {
    if (err) { return callback(err); }
    return callback(null, client);
  });
});

// Register supported grant types.
//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

// Grant authorization codes.  The callback takes the `client` requesting
// authorization, the `redirectUri` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a code, which is bound to these
// values, and will be exchanged for an access token.

server.grant(oauth2orize.grant.code(function(client, redirectUri, user, ares,areq, callback) {
  // Create a new authorization code
  console.log(areq);
  var code = new Code({
    value: uid(16),
    clientId: client._id,
    redirectUri: redirectUri,
    userId: user._id,
	scope:areq.scope
  });

  // Save the auth code and check for errors
  code.save(function(err) {
    if (err) { return callback(err); }

    callback(null, code.value);
  });
}));


server.grant(oauth2orize_ext.grant.codeIdToken(
  function(client, redirect_uri, user,ares, areq,callback){
	  var Id = jwtDecode(areq.request).claims.userinfo.openbanking_intent_id.value;
   var code = new Code({
    value: uid(16),
    clientId: client._id,
    redirectUri: redirect_uri,
    userId: user._id,
	scope:areq.scope,
	IntentId:Id
  });

  // Save the auth code and check for errors
  code.save(function(err) {
    if (err) { return callback(err); }

    callback(null, code.value);
  });
    callback(null, code.value);
  },
  function(client, user,req, callback){
  
  
 
// HS256 secrets are typically 128-bit random strings, for example hex-encoded:
// var secret = Buffer.from('fe1a1915a379f3be5394b64d14794932', 'hex')
 
// encode
//	var token = jwtDecode(req.request);
	id_token = generate_id_token(req.request);

    callback(null, id_token);
  }
));


// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectUri` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.

server.exchange(oauth2orize.exchange.code(function(client, code, redirectUri, callback) {
	console.log(client);	
  Code.findOne({ value: code }, function (err, authCode) {
    if (err) { return callback(err); }
	console.log(authCode);
    if (authCode === undefined) { return callback(null, false); }
    if (client._id.toString() !== authCode.clientId) { return callback(null, false); }
    if (redirectUri !== authCode.redirectUri) { return callback(null, false); }

    // Delete auth code now that it has been used
    authCode.remove(function (err) {
      if(err) { return callback(err); }

      // Create a new access token
      var token = new Token({
        value: uid(256),
        clientId: authCode.clientId,
        userId: authCode.userId,
		scope:authCode.scope,
		IntentId:authCode.IntentId,
		IssuedAt:new Date().getTime(),
		ExpiresIn:120,
		Status:true
      });

      // Save the access token and check for errors
      token.save(function (err) {
        if (err) { return callback(err); }
		var resToken={};
		resToken.value=token.value;
		resToken.expires_in=token.ExpiresIn;
        callback(null, resToken);
      });
    });
  });
}));

// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectUri` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `callback` callback must be invoked with
// a `client` instance, as well as the `redirectUri` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view. 

exports.authorization = [
  server.authorization(function(clientId, redirectUri, callback) {
	  

    Client.findOne({ id: clientId }, function (err, client) {
      if (err) { return callback(err); }

      return callback(null, client, redirectUri);
    });
  }),
  function(req, res){
    res.render('dialog', { transactionID: req.oauth2.transactionID, user: req.user, client: req.oauth2.client });
  }
]

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

exports.decision = [
  server.decision()
]

// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

exports.token = [
  server.token(),
  server.errorHandler()
]


exports.token1 = [
  server1.token(),
  server1.errorHandler()
]

/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */
function uid (len) {
  var buf = []
    , chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    , charlen = chars.length;

  for (var i = 0; i < len; ++i) {
    buf.push(chars[getRandomInt(0, charlen - 1)]);
  }

  return buf.join('');
};

/**
 * Return a random int, used by `utils.uid()`
 *
 * @param {Number} min
 * @param {Number} max
 * @return {Number}
 * @api private
 */

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generate_id_token(token)
{   
	
	var decoded = jwtDecode(token);
	
	var payload = {};
	payload.iss='https://api.bank.com';
	payload.iat=Math.floor(new Date() / 1000);
	payload.sub='contact@bank.com';
	payload.acr='urn:openbanking:psd2:sca';
	payload.openbanking_intent_id=decoded.claims.userinfo.openbanking_intent_id.value;
	payload.aud=decoded.client_id;
	payload.nonce=decoded.nonce;
	payload.exp=Math.floor(new Date() / 1000);
	var id_token = jwt.encode(payload, 'xxx');
	return id_token;
}


//Client Credentials
/*server.exchange(oauth2orize.exchange.clientCredentials(function(client, scope, done) {
    var token = 'aaa'
    //var tokenHash = crypto.createHash('sha1').update(token).digest('hex')
    var expiresIn = 1800
    var expirationDate = new Date(new Date().getTime() + (expiresIn * 1000))
	return done(null, token, {expires_in: expiresIn})
  /*  db.collection('accessTokens').save({token: tokenHash, expirationDate: expirationDate, clientId: client.clienId, scope: scope}, function(err) {
        if (err) return done(err)
        
    })
}))*/

     server1.exchange(oauth2orize.exchange.clientCredentials(function(client, scope, req,done) {
		 console.log('inside exchange '+req.grant_type+ client);
		       // Create a new access token
      var token = new Token({
        value: uid(256),
        clientId: client.userId,
		scope:scope,
		IssuedAt:new Date().getTime(),
		ExpiresIn:120,
		Status:true,
		userId:'123',
		IntentId:'dfd'
      });

      // Save the access token and check for errors
      token.save(function (err) {
        if (err) { 
		console.log(err);
		return done(err); }
		var resToken={};
		resToken.value=token.value;
		resToken.expires_in=token.ExpiresIn;
        done(null, resToken);
      });
		
      
      }));
