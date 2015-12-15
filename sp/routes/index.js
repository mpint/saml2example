var express = require('express');
var router = express.Router();
var saml2 = require('saml2-js');
var fs = require('fs');
var btoa = require('btoa');

// Create service provider
var sp_options = {
  entity_id: "http://localhost:4000/metadata.xml",
  assert_endpoint: "http://localhost:4000/assert",
  certificate: fs.readFileSync("./test.crt").toString(),
  private_key: fs.readFileSync("./test.pem").toString()
};

// Create identity provider
var idp_options = {
  sso_login_url: "http://localhost:3000/login",
  sso_logout_url: "http://localhost:3000/logout",
  certificates: [fs.readFileSync('test.crt'), fs.readFileSync("./test2.crt").toString()]
};

var sp = new saml2.ServiceProvider(sp_options);
var idp = new saml2.IdentityProvider(idp_options);

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Service Provider', port:  4000});
});


// ------ Define express endpoints ------

// Endpoint to retrieve metadata
router.get("/metadata.xml", function(req, res) {
  res.type('application/xml');
  res.send(sp.create_metadata());
});

// Starting point for sso login
router.get("/login", function(req, res) {
  sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {
    if (err != null)
      return res.sendStatus(500);

    res.redirect(login_url);
  });
});

// Assert endpoint for when login completes (SP)
router.post("/assert", function(req, res) {
  var decoded = decodeURI(req.body.SAMLResponse);
  var options = {request_body: {SAMLResponse: decoded}};

  sp.post_assert(idp, options, function(err, saml_response) {
    if (err != null) {
      console.log(err);
      return res.sendStatus(500);
    }

    // Save name_id and session_index for logout
    // Note:  In practice these should be saved in the user session, not globally.
    name_id = saml_response.user.name_id;
    session_index = saml_response.user.session_index;

    res.send("Hello #{saml_response.user.name_id}!");
  });
});

// Starting point for logout
router.get("/logout", function(req, res) {
  var options = {
    name_id: name_id,
    session_index: session_index
  };

  sp.create_logout_request_url(idp, options, function(err, logout_url) {
    if (err != null)
      return res.sendStatus(500);
    res.redirect(logout_url);
  });
});

module.exports = router;
