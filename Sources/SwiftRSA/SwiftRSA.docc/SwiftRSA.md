# ``SwiftRSA``

RSA Public-Key Cryptography

## Overview

SwiftRSA provides RSA cryptography in Swift. This encompasses:

* RSA key pair creation
* Loading existing keys from their PEM and DER encodings
* Encryption and decryption using either the PKCS1 scheme or the OAEP scheme
* Signing and verifying using either the PKCS1- or the PSS signature scheme

### Encrypt and Decrypt

You need a public key - say `pubKey` - to encrypt a message and the corresponding private key - say `privKey` - to decrypt it.

**PKCS1 Example**

```swift
let pkcs1Cipher = try pubKey.encryptPKCS1(message: [1, 2, 3])
let clearText = try privKey.decryptPKCS1(cipher: pkcs1Cipher)
```

**OAEP Example**

```swift
let oaepCipher = try pubKey.encryptOAEP(message: [1, 2, 3], kind: .SHA3_256, label: [4, 5, 6])
let clearText = try privKey.decryptOAEP(cipher: oaepCipher, kind: .SHA3_256, label: [4, 5, 6])
```

### Sign and Verify

You need a private key - say `privKey` - to sign a message and the corresponding public key - say `pubKey` - to verify the signature.

**PKCS1 Example**

```swift
let pkcs1Signature = try privKey.signPKCS1(message: [1, 2, 3], kind: .SHA3_256)
let ok = pubKey.verifyPKCS1(signature: pkcs1Signature, message: [1, 2, 3], kind: .SHA3_256)
```

**PSS Example**

```swift
let pssSignature = try privKey.signPSS(message: [1, 2, 3], kind: .SHA3_256)
let ok = pubKey.verifyPSS(signature: pssSignature, message: [1, 2, 3], kind: .SHA3_256)
```

### Usage

To use SwiftRSA, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftRSA", from: "2.6.0"),
]
```

SwiftRSA itself depends on the [ASN1](https://leif-ibsen.github.io/ASN1/documentation/asn1), [BigInt](https://leif-ibsen.github.io/BigInt/documentation/bigint) and [Digest](https://leif-ibsen.github.io/Digest/documentation/digest) packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.7.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.21.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.13.0"),
],
```

>Important:
SwiftRSA requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Classes

- ``SwiftRSA/RSA``
- ``SwiftRSA/RSAPrivateKey``
- ``SwiftRSA/RSAPublicKey``

### Type Aliases

- ``SwiftRSA/Byte``
- ``SwiftRSA/Bytes``

### Additional Information

- <doc:KeyManagement>
- <doc:Performance>
- <doc:References>

