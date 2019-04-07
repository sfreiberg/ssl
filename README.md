# SSL

## About

SSL is a simple command line utility to get common information from an SSL/TLS endpoint. For example if you want to find out when a cert expires. An example is show below in the Usage section. All of this information is available via other tools but `ssl` is very simple with no arcane syntax to remember.

## Releases

Binary releases for common platforms are available on the Github releases tab.

## Example

```bash
$ ssl google.com gmail.com
google.com:443
  Expired:	false
  Start:	2019-03-01 09:43:57 +0000 UTC
  End:		2019-05-24 09:25:00 +0000 UTC
  Valid Host:	true
  Version:	TLS 3.0
  Cipher Suite:	ECDHE_ECDSA/AES_128_GCM/SHA256
gmail.com:443
  Expired:	false
  Start:	2019-03-01 09:28:34 +0000 UTC
  End:		2019-05-24 09:24:00 +0000 UTC
  Valid Host:	true
  Version:	TLS 3.0
  Cipher Suite:	ECDHE_RSA/AES_128_GCM/SHA
```

## Limitations

SSL does not currently report all possible SSL/TLS ciphers. Only the cipher that the client/server agreed upon.