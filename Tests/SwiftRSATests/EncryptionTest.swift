//
//  EncryptionTest.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 11/02/2022.
//

import XCTest

class EncryptionTest: XCTestCase {

    let messages = [
        "",
        "0000000000000000000000000000000000000000",
        "54657374",
        "61",
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"]
    let labels: [Bytes] = [
        [],
        [0, 0, 0],
        [1, 2, 3]
    ]

    func doTest1(_ size: Int) throws {
        let (pub, priv) = try RSA.makeKeyPair(size: size, exponent: RSA.F4)
        for message in messages {
            let msg = Utilities.hex2bytes(message)
            try doTest2(pub, priv, msg)
        }
    }

    func doTest2(_ pub: RSAPublicKey, _ priv: RSAPrivateKey, _ msg: Bytes) throws {
        let cipher1 = try pub.encryptPKCS1(message: msg)
        let msg1 = try priv.decryptPKCS1(cipher: cipher1)
        XCTAssertEqual(msg, msg1)
        for mda in RSA.MessageDigestAlgorithm.allCases {
            do {
                for l in labels {
                    let cipher2 = try pub.encryptOAEP(message: msg, mda: mda, label: l)
                    let msg2 = try priv.decryptOAEP(cipher: cipher2, mda: mda, label: l)
                    XCTAssertEqual(msg, msg2)
                }
            } catch RSA.Exception.encrypt {
                let md = MessageDigest(mda)
                XCTAssertTrue(msg.count > pub.n.magnitude.count * 8 - 2 * md.digestLength - 2)
            }
        }
    }

    func test1() throws {
        var size = 1024
        for _ in 0 ..< 3 {
            try doTest1(size)
            size *= 2
        }
    }
    
    func test2() throws {
        var size = 1088
        for _ in 0 ..< 10 {
            try doTest1(size)
            size += 64
        }
    }

}
