# Encrypt and Decrypt

## 

You need a public key - say `pubKey` - to encrypt a message and the corresponding private key - say `privKey` - to decrypt it.

### PKCS1 Example
```swift
let pkcs1Cipher = try pubKey.encryptPKCS1(message: [1, 2, 3])
let clearText = try privKey.decryptPKCS1(cipher: pkcs1Cipher)
```

### OAEP Example
```swift
let oaepCipher = try pubKey.encryptOAEP(message: [1, 2, 3], kind: .SHA3_256, label: [4, 5, 6])
let clearText = try privKey.decryptOAEP(cipher: oaepCipher, kind: .SHA3_256, label: [4, 5, 6])
```
