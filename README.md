# SSL

## About

SSL is a simple command line utility to get common information from an SSL/TLS endpoint. For example if you want to find out when a cert expires. An example is show below in the Usage section. All of this information is available via other tools but `ssl` is very simple with no arcane syntax to remember.

## Releases

Binary releases for common platforms are available on the Github [releases](https://github.com/sfreiberg/ssl/releases) page.

New releases are built and published automatically by [GoReleaser](https://goreleaser.com) when a version tag is pushed:

```bash
git tag v1.3.0
git push origin v1.3.0
```

## Example

```bash
$ ssl google.com gmail.com
google.com:443
  Expired:		false
  Start:		2026-09-18 20:00:19 +0000 UTC
  End:			2026-12-11 20:00:18 +0000 UTC
  Valid Host:		true
  Version:		TLS 1.3
  Cipher Suite:		AES_128_GCM/SHA256
  Serial Number:	95 83 99 D5 1C BB B9 0E 0A 02 7A CB A3 D2 42 ED
  SHA256 Fingerprint:	C0 C4 49 95 A7 12 E9 78 CF 5D DE 65 3D C0 D4 81 64 D4 96 1C EA 25 ED 73 45 40 06 1A C5 E8 0F 48
gmail.com:443
  Expired:		false
  Start:		2026-09-18 20:01:45 +0000 UTC
  End:			2026-12-11 20:01:44 +0000 UTC
  Valid Host:		true
  Version:		TLS 1.3
  Cipher Suite:		AES_128_GCM/SHA256
  Serial Number:	44 15 D7 6F 46 E0 96 E3 0A 08 4D CF FD 8E EF 42
  SHA256 Fingerprint:	B9 31 DD 41 DB 79 AB 6A 4B C8 64 AC 9E 78 AB AD C2 EE 78 AD 1F 0F 4E BA 6A E7 8A 1C D9 3C CE 20
```

## Limitations

SSL does not currently report all possible SSL/TLS ciphers. Only the cipher that the client/server agreed upon.