# Sign and Verify

## 

You need a private key - say `privKey` - to sign a message and the corresponding public key - say `pubKey` - to verify the signature.

### PKCS1 Example
```swift
let pkcs1Signature = try privKey.signPKCS1(message: [1, 2, 3], kind: .SHA3_256)
let ok = pubKey.verifyPKCS1(signature: pkcs1Signature, message: [1, 2, 3], kind: .SHA3_256)
```

### PSS Example
```swift
let pssSignature = try privKey.signPSS(message: [1, 2, 3], kind: .SHA3_256)
let ok = pubKey.verifyPSS(signature: pssSignature, message: [1, 2, 3], kind: .SHA3_256)
```
