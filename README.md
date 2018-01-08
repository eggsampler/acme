# acme
Go library implementation for ACME v2 

## Current Issues
* Some tests fail because the Location header is not present in the finalize order endpoint
  * Could work around this by copying the Location from the existing one, or just wait for this: https://github.com/letsencrypt/boulder/pull/3336
* Key Rollover doesn't work yet
  * https://github.com/letsencrypt/boulder/issues/3340
* Certificate revocation doesn't work yet
  * Need to use the certificate jwk instead of account
  * https://github.com/ietf-wg-acme/acme/pull/383

## TODO
* Rewrite JWK stuff, needs to be nicer to support the inner/outer JWK for key rollover and certificate key for revocation
* s/error/errors
  * https://github.com/letsencrypt/boulder/issues/3339
