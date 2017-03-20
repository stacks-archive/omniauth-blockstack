var signingKey = null
var authRequest = blockstack.makeAuthRequest(signingKey, domainName, manifestURI, redirectURI)
blockstack.redirectUserToSignIn(authRequest)
