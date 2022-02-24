//
//  MD.swift
//  SwiftRSATest
//
//  Created by Leif Ibsen on 03/02/2022.
//

typealias Word = UInt32
typealias Words = [Word]
typealias Long = UInt64
typealias Longs = [Long]

protocol MessageDigestImpl {
    func doBuffer(_ buffer: inout Bytes, _ hw: inout Words, _ hl: inout Longs)
    func doReset(_ hw: inout Words, _ hl: inout Longs)
    func padding(_ totalBytes: Int, _ blockSize: Int) -> Bytes
}

class MessageDigest {
    
    let impl: MessageDigestImpl
    let keccak: Bool
    let digestLength: Int
    var totalBytes: Int
    var bytes: Int
    var buffer: Bytes
    var hw: Words
    var hl: Longs
    var S: Bytes
    let digestInfo: Bytes
    
    init(_ algorithm: RSA.MessageDigestAlgorithm) {
        switch algorithm {
        case .SHA1:
            self.impl = SHA1()
            self.keccak = false
            self.digestLength = 20
            self.buffer = Bytes(repeating: 0, count: 64)
            self.hw = Words(repeating: 0, count: 5)
            self.hl = Longs(repeating: 0, count: 0)
            self.S = Bytes(repeating: 0, count: 0)
            self.digestInfo = [48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20]
        case .SHA2_224:
            self.impl = SHA2_256(true)
            self.keccak = false
            self.digestLength = 28
            self.buffer = Bytes(repeating: 0, count: 64)
            self.hw = Words(repeating: 0, count: 8)
            self.hl = Longs(repeating: 0, count: 0)
            self.S = Bytes(repeating: 0, count: 0)
            self.digestInfo = [48, 45, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 4, 5, 0, 4, 28]
        case .SHA2_256:
            self.impl = SHA2_256(false)
            self.keccak = false
            self.digestLength = 32
            self.buffer = Bytes(repeating: 0, count: 64)
            self.hw = Words(repeating: 0, count: 8)
            self.hl = Longs(repeating: 0, count: 0)
            self.S = Bytes(repeating: 0, count: 0)
            self.digestInfo = [48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32]
        case .SHA2_384:
            self.impl = SHA2_512(true)
            self.keccak = false
            self.digestLength = 48
            self.buffer = Bytes(repeating: 0, count: 128)
            self.hw = Words(repeating: 0, count: 0)
            self.hl = Longs(repeating: 0, count: 8)
            self.S = Bytes(repeating: 0, count: 0)
            self.digestInfo = [48, 65, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 4, 48]
        case .SHA2_512:
            self.impl = SHA2_512(false)
            self.keccak = false
            self.digestLength = 64
            self.buffer = Bytes(repeating: 0, count: 128)
            self.hw = Words(repeating: 0, count: 0)
            self.hl = Longs(repeating: 0, count: 8)
            self.S = Bytes(repeating: 0, count: 0)
            self.digestInfo = [48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 4, 64]
        case .SHA3_224:
            self.impl = SHA3()
            self.keccak = true
            self.digestLength = 28
            self.buffer = Bytes(repeating: 0, count: 144)
            self.hw = Words(repeating: 0, count: 0)
            self.hl = Longs(repeating: 0, count: 0)
            self.S = Bytes(repeating: 0, count: 200)
            self.digestInfo = [48, 45, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 7, 5, 0, 4, 28]
        case .SHA3_256:
            self.impl = SHA3()
            self.keccak = true
            self.digestLength = 32
            self.buffer = Bytes(repeating: 0, count: 136)
            self.hw = Words(repeating: 0, count: 0)
            self.hl = Longs(repeating: 0, count: 0)
            self.S = Bytes(repeating: 0, count: 200)
            self.digestInfo = [48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 8, 5, 0, 4, 32]
        case .SHA3_384:
            self.impl = SHA3()
            self.keccak = true
            self.digestLength = 48
            self.buffer = Bytes(repeating: 0, count: 104)
            self.hw = Words(repeating: 0, count: 0)
            self.hl = Longs(repeating: 0, count: 0)
            self.S = Bytes(repeating: 0, count: 200)
            self.digestInfo = [48, 65, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 9, 5, 0, 4, 48]
        case .SHA3_512:
            self.impl = SHA3()
            self.keccak = true
            self.digestLength = 64
            self.buffer = Bytes(repeating: 0, count: 72)
            self.hw = Words(repeating: 0, count: 0)
            self.hl = Longs(repeating: 0, count: 0)
            self.S = Bytes(repeating: 0, count: 200)
            self.digestInfo = [48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 10, 5, 0, 4, 64]
        }
        self.totalBytes = 0
        self.bytes = 0
        self.impl.doReset(&self.hw, &self.hl)
    }

    func reset() {
        for i in 0 ..< self.buffer.count {
            self.buffer[i] = 0
        }
        for i in 0 ..< self.S.count {
            self.S[i] = 0
        }
        self.totalBytes = 0
        self.bytes = 0
        self.impl.doReset(&self.hw, &self.hl)
    }
    
    func update(_ input: Bytes) {
        var remaining = input.count
        var ndx = 0
        while remaining > 0 {
            let a = remaining < self.buffer.count - self.bytes ? remaining : self.buffer.count - self.bytes
            for i in 0 ..< a {
                self.buffer[self.bytes + i] = input[ndx + i]
            }
            self.bytes += a
            ndx += a
            remaining -= a
            if self.bytes == self.buffer.count {
                if self.keccak {
                    for i in 0 ..< self.buffer.count {
                        self.S[i] ^= self.buffer[i]
                    }
                    self.impl.doBuffer(&self.S, &self.hw, &self.hl)
                } else {
                    self.impl.doBuffer(&self.buffer, &self.hw, &self.hl)
                }
                self.bytes = 0
            }
        }
        self.totalBytes += input.count
    }
    
    func digest() -> Bytes {
        var md = Bytes(repeating: 0, count: self.digestLength)
        update(self.impl.padding(self.totalBytes, self.buffer.count))
        if self.keccak {
            var Z = Bytes(repeating: 0, count: 0)
            while true {
                for i in 0 ..< self.buffer.count {
                    Z.append(S[i])
                }
                if Z.count < self.digestLength {
                    self.impl.doBuffer(&self.S, &self.hw, &self.hl)
                } else {
                    for i in 0 ..< self.digestLength {
                        md[i] = Z[i]
                    }
                    break
                }
            }
        } else if self.digestLength > 32 {
                
            // SHA2_384 and SHA2_512
                
            for i in 0 ..< self.digestLength {
                md[i] = Byte((self.hl[i >> 3] >> ((7 - (i & 0x7)) * 8)) & 0xff)
            }
        } else {
            
            // SHA2_224 and SHA2_256

            for i in 0 ..< self.digestLength {
                md[i] = Byte((self.hw[i >> 2] >> ((3 - (i & 0x3)) * 8)) & 0xff)
            }
        }
        self.reset()
        return md
    }
    
}
