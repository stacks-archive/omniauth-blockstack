var authRequest = blockstack.makeAuthRequest(signingKey, appManifest)
blockstack.redirectUserToSignIn(authRequest)
