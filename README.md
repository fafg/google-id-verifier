# google-id-verifier

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/8437df4db93c43648a9979cab36fee7e)](https://app.codacy.com/manual/fafg/google-id-verifier?utm_source=github.com&utm_medium=referral&utm_content=fafg/google-id-verifier&utm_campaign=Badge_Grade_Dashboard)

Golang port of [OAuth2Client.prototype.verifyIdToken](https://github.com/google/google-auth-library-nodejs/blob/master/src/auth/oauth2client.ts) from [google-auth-library-nodejs](https://github.com/google/google-auth-library-nodejs)

Verifies Google-issued ID tokens without making http request to the tokeninfo API.

## Usage

```go

import (
    "github.com/serjlee/google-id-verifier"
)

v := googleIDVerifier.CertsVerifier{}
aud := "xxxxxx-yyyyyyy.apps.googleusercontent.com"
err := v.VerifyIDToken(TOKEN, []string{
    aud,
})
if err == nil {
    claimSet, err := googleIDVerifier.Decode(TOKEN)
    // claimSet.Iss,claimSet.Email ... (See claimset.go)
}
```

## Features

- Fetch public key from www.googleapis.com/oauth2/v3/certs
- Respect cache-control in response from www.googleapis.com/oauth2/v3/certs
- JWT Parser
- Check Signature 
- Check IssueTime, ExpirationTime with ClockSkew
- Check Issuer
- Check Audience

## Deps

- golang.org/x/oauth2/jws

## See also

- http://stackoverflow.com/questions/36716117/validating-google-sign-in-id-token-in-go#
- https://github.com/GoogleIdTokenVerifier/GoogleIdTokenVerifier
