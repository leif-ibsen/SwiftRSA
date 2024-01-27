# ``SwiftRSA/RSAPrivateKey``

## Topics

### Properties

- ``n``
- ``e``
- ``d``
- ``p``
- ``q``
- ``dP``
- ``dQ``
- ``qInv``
- ``publicKey``
- ``description``

### Constructors

- ``init(der:format:)``
- ``init(pem:format:)``

### Methods

- ``derEncoded(format:)``
- ``pemEncoded(format:)``
- ``decryptPKCS1(cipher:)``
- ``signPKCS1(message:kind:)``
- ``decryptOAEP(cipher:kind:label:)``
- ``signPSS(message:kind:)``
