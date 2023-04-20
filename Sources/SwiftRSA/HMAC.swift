//
//  HMAC.swift
//  SwiftRSA
//
//  Created by Leif Ibsen on 26/02/2022.
//

class HMAC {
    
    static let OPAD = Byte(0x5c)
    static let IPAD = Byte(0x36)
    
    let md: MessageDigest
    let blockSize: Int
    
    init(_ mda: RSA.MessageDigestAlgorithm) {
        self.md = MessageDigest(mda)
        self.blockSize = self.md.buffer.count
    }

    func hmac(_ key: Bytes, _ message: Bytes) -> Bytes {
        var macKey = Bytes(repeating: 0, count: self.blockSize)
        if key.count > self.blockSize {
            self.md.update(key)
            let x = self.md.digest()
            for i in 0 ..< x.count {
                macKey[i] = x[i]
            }
        } else {
            for i in 0 ..< key.count {
                macKey[i] = key[i]
            }
        }
        var iKeyPad = Bytes(repeating: 0, count: self.blockSize)
        var oKeyPad = Bytes(repeating: 0, count: self.blockSize)
        for i in 0 ..< self.blockSize {
            iKeyPad[i] = macKey[i] ^ HMAC.IPAD
            oKeyPad[i] = macKey[i] ^ HMAC.OPAD
        }
        self.md.update(iKeyPad)
        self.md.update(message)
        let x = self.md.digest()
        self.md.update(oKeyPad)
        self.md.update(x)
        return self.md.digest()
    }
}
