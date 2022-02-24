//
//  SHA3.swift
//  SwiftRSATest
//
//  Created by Leif Ibsen on 16/02/2022.
//

class SHA3: MessageDigestImpl {
    
    let RC_CONSTANTS: Longs = [
    0x01, 0x8082, 0x800000000000808a, 0x8000000080008000, 0x808b, 0x80000001, 0x8000000080008081,
    0x8000000000008009, 0x8a, 0x88, 0x80008009, 0x8000000a, 0x8000808b, 0x800000000000008b,
    0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x800a,
    0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008]

    var state: Bytes
    var lanes: Longs
    
    init() {
        self.state = Bytes(repeating: 0, count: 200)
        self.lanes = Longs(repeating: 0, count: 25)
    }
    
    func doReset(_ hw: inout Words, _ hl: inout Longs) {
        self.state = Bytes(repeating: 0, count: 200)
    }
    
    func toLanes(_ buffer: Bytes) {
        for y in 0 ..< 5 {
            for x in 0 ..< 5 {
                var b = Long(0)
                for i in 0 ..< 8 {
                    b |= Long(buffer[8 * (5 * y + x) + i]) << (i * 8)
                }
                self.lanes[5 * y + x] = b
            }
        }
    }
    
    func fromLanes(_ buffer: inout Bytes) {
        for y in 0 ..< 5 {
            for x in 0 ..< 5 {
                var b = self.lanes[5 * y + x]
                for i in 0 ..< 8 {
                    buffer[8 * (5 * y + x) + i] = Byte(b & 0xff)
                    b >>= 8
                }
            }
        }
    }
    
    func doBuffer(_ buffer: inout Bytes, _ hw: inout Words, _ hl: inout Longs) {
        toLanes(buffer)
        for i in 0 ..< 24 {
            theta()
            phiRho()
            chi()
            iota(i)
        }
        fromLanes(&buffer)
    }
    
    func theta() {
        let c0 = self.lanes[0] ^ self.lanes[5] ^ self.lanes[10] ^ self.lanes[15] ^ self.lanes[20]
        let c1 = self.lanes[1] ^ self.lanes[6] ^ self.lanes[11] ^ self.lanes[16] ^ self.lanes[21]
        let c2 = self.lanes[2] ^ self.lanes[7] ^ self.lanes[12] ^ self.lanes[17] ^ self.lanes[22]
        let c3 = self.lanes[3] ^ self.lanes[8] ^ self.lanes[13] ^ self.lanes[18] ^ self.lanes[23]
        let c4 = self.lanes[4] ^ self.lanes[9] ^ self.lanes[14] ^ self.lanes[19] ^ self.lanes[24]
        let d0 = c4 ^ SHA3.rotateLeft(c1, 1)
        let d1 = c0 ^ SHA3.rotateLeft(c2, 1)
        let d2 = c1 ^ SHA3.rotateLeft(c3, 1)
        let d3 = c2 ^ SHA3.rotateLeft(c4, 1)
        let d4 = c3 ^ SHA3.rotateLeft(c0, 1)
        for y in stride(from: 0, through: 20, by: 5) {
            self.lanes[y] ^= d0
            self.lanes[y + 1] ^= d1
            self.lanes[y + 2] ^= d2
            self.lanes[y + 3] ^= d3
            self.lanes[y + 4] ^= d4
        }
    }
    
    func phiRho() {
        let tmp = SHA3.rotateLeft(self.lanes[10], 3)
        self.lanes[10] = SHA3.rotateLeft(self.lanes[1], 1)
        self.lanes[1] = SHA3.rotateLeft(self.lanes[6], 44)
        self.lanes[6] = SHA3.rotateLeft(self.lanes[9], 20)
        self.lanes[9] = SHA3.rotateLeft(self.lanes[22], 61)
        self.lanes[22] = SHA3.rotateLeft(self.lanes[14], 39)
        self.lanes[14] = SHA3.rotateLeft(self.lanes[20], 18)
        self.lanes[20] = SHA3.rotateLeft(self.lanes[2], 62)
        self.lanes[2] = SHA3.rotateLeft(self.lanes[12], 43)
        self.lanes[12] = SHA3.rotateLeft(self.lanes[13], 25)
        self.lanes[13] = SHA3.rotateLeft(self.lanes[19], 8)
        self.lanes[19] = SHA3.rotateLeft(self.lanes[23], 56)
        self.lanes[23] = SHA3.rotateLeft(self.lanes[15], 41)
        self.lanes[15] = SHA3.rotateLeft(self.lanes[4], 27)
        self.lanes[4] = SHA3.rotateLeft(self.lanes[24], 14)
        self.lanes[24] = SHA3.rotateLeft(self.lanes[21], 2)
        self.lanes[21] = SHA3.rotateLeft(self.lanes[8], 55)
        self.lanes[8] = SHA3.rotateLeft(self.lanes[16], 45)
        self.lanes[16] = SHA3.rotateLeft(self.lanes[5], 36)
        self.lanes[5] = SHA3.rotateLeft(self.lanes[3], 28)
        self.lanes[3] = SHA3.rotateLeft(self.lanes[18], 21)
        self.lanes[18] = SHA3.rotateLeft(self.lanes[17], 15)
        self.lanes[17] = SHA3.rotateLeft(self.lanes[11], 10)
        self.lanes[11] = SHA3.rotateLeft(self.lanes[7], 6)
        self.lanes[7] = tmp
    }
    
    func chi() {
        for y in stride(from: 0, through: 20, by: 5) {
            let ay0 = self.lanes[y]
            let ay1 = self.lanes[y + 1]
            let ay2 = self.lanes[y + 2]
            let ay3 = self.lanes[y + 3]
            let ay4 = self.lanes[y + 4]
            self.lanes[y] = ay0 ^ ((~ay1) & ay2)
            self.lanes[y + 1] = ay1 ^ ((~ay2) & ay3)
            self.lanes[y + 2] = ay2 ^ ((~ay3) & ay4)
            self.lanes[y + 3] = ay3 ^ ((~ay4) & ay0)
            self.lanes[y + 4] = ay4 ^ ((~ay0) & ay1)
        }
    }
    
    func iota(_ r: Int) {
        self.lanes[0] ^= RC_CONSTANTS[r]
    }

    func padding(_ totalBytes: Int, _ blockSize: Int) -> Bytes {
        let x = ((totalBytes + blockSize) / blockSize) * blockSize - totalBytes
        var b = Bytes(repeating: 0, count: x)
        b[0] = 0x06
        b[x - 1] |= 0x80
        return b
    }

    static func rotateLeft(_ x: Long, _ n: Int) -> Long {
        return (x << n) | (x >> (64 - n))
    }

}
