# acme
Go library implementation for ACME v2 

## Current Issues
* Key Rollover is implemented, but boulder has an issue where it thinks the new account already exists
  * https://github.com/letsencrypt/boulder/issues/3340
* Issuer certificates need non-acme specific url in boulder
  * Boulder doesn't return a pem chain OR an up Link header in the fetch certificate endpoint (yet)
  * Implemented non-standard FetchIssuerCertificate func
  * https://github.com/letsencrypt/boulder/issues/3291

## TODO
* s/error/errors/
  * https://github.com/letsencrypt/boulder/issues/3339
* Properly handle badNonce errors and gracefully retry
  * An assumption is made that all get requests will contain a nonce reply
  * This could cause a problem: https://github.com/letsencrypt/boulder/issues/3272