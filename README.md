# cms for Go
[Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652) is a syntax used to digitally sign, digest, authenticate, or encrypt arbitrary message content.
The Go library lets you create and interperit CMS messages.

## Status

Current supported CMS content types are:
* Signed Data Content Type

Digest algorithms supported:
* SHA1 (strongly discouraged)
* SHA256

Signature algorithms supported:
* rsa

## Install

```bash
go get github.com/hiddedorhout/cms
```

## Example

A reference implementation can be found in cms_test.go