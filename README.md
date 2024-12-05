[![Check](https://github.com/fortime/dns-renew/actions/workflows/check.yml/badge.svg)](https://github.com/fortime/dns-renew/actions/workflows/check.yml)

# dns-renew

It is a cli tool to update your domain's ip. It will query the ip of your domain through dns / doh / dot, and compare the result with the ip you provided. If it is not matched, it will update the record.

You can provide a static ip or tell the tool to get your public ip through services like [ifconfig.io](https://ifconfig.io) or [sslip.io](https://sslip.io/). One is HTTP-based, and the other is DNS-based.

## Supported DNS Hosting Provider

* Cloudflare
* Any provider which supports using http api with basic auth to update a dns record.
* Any provider which supports using http api with bearer token to update a dns record.

## Config File Example

[Examples](https://github.com/fortime/dns-renew/tree/main/examples)
