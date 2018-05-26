# eggsampler/acme

[![GoDoc](https://godoc.org/github.com/eggsampler/acme?status.svg)](https://godoc.org/github.com/eggsampler/acme)

## About

This is a Go client library implementation for the [ACME v2 revision 10](https://tools.ietf.org/html/draft-ietf-acme-acme-10) specification, specifically for use with the [Let's Encrypt](https://letsencrypt.org/) service. 

The library is designed to provide a wrapper over exposed directory endpoints and wrap the objects in easy to use structures.

## Example

A simple [certbot](https://certbot.eff.org/)-like example is provided in the examples/certbot directory.
This code demonstrates account registation, new order submission, fulfilling challenges, finalising an order and fetching the issued certificate chain.

An example of how to use the autocert package is also provided in examples/autocert.

## Tests

The tests are designed to be run against a local instance of [boulder](https://github.com/letsencrypt/boulder) running the `config-next` configuration along with the FAKE_DNS variable set.