# acme
Go library implementation for ACME v2 

## Current Issues
* Fetching orders list isn't implemented in boulder
  * https://github.com/letsencrypt/boulder/issues/3335

## TODO
* Properly handle badNonce errors and gracefully retry
  * An assumption is made that all get requests will contain a nonce reply
  * This could cause a problem: https://github.com/letsencrypt/boulder/issues/3272
* Write up a better readme