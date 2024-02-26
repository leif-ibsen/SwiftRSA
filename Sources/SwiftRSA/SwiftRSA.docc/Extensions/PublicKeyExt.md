# ``SwiftRSA/RSAPublicKey``

The public key

## Topics

### Properties

- ``n``
- ``e``
- ``description``

### Constructors

- ``init(der:format:)``
- ``init(pem:format:)``

### Methods

- ``derEncoded(format:)``
- ``pemEncoded(format:)``
- ``encryptPKCS1(message:)``
- ``verifyPKCS1(signature:message:kind:)``
- ``encryptOAEP(message:kind:label:)``
- ``verifyPSS(signature:message:kind:)``
