# Golang Time-Based OTP Generator

Golang implementation of the [Time-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc6238.txt).

## Usage

```
go run totp.go <shared secret>
```

The shared secret is provided by the service when first setting up time based OTP 2FA.
This is a base32 encoding of 10 bytes.

## References

Adapted from http://jacob.jkrall.net/totp/