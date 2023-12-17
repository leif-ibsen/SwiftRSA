//
//  SignatureTest.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 11/02/2022.
//

import XCTest
@testable import SwiftRSA
import Digest

class SignatureTest: XCTestCase {

    let messages = [
        "",
        "0000000000000000000000000000000000000000",
        "54657374",
        "313233343030",
        "61",
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"]
    
    func doTest1(_ size: Int) throws {
        let (pub, priv) = try RSA.makeKeyPair(size: size, exponent: RSA.F4)
        for kind in MessageDigest.Kind.allCases {
            for message in messages {
                let msg = Utilities.hex2bytes(message)
                try doTest2(pub, priv, kind, msg)
            }
        }
    }

    func doTest2(_ pub: RSAPublicKey, _ priv: RSAPrivateKey, _ kind: MessageDigest.Kind, _ msg: Bytes) throws {
        do {
            let sig1 = try priv.signPKCS1(message: msg, kind: kind)
            XCTAssertTrue(pub.verifyPKCS1(signature: sig1, message: msg, kind: kind))
        } catch RSA.Exception.sign {
            let md = MessageDigest(kind)
            let di = RSA.digestInfo(kind)
            XCTAssertTrue(priv.n.magnitude.count * 8 < di.count + md.digestLength + 11)
        }
        do {
            let sig2 = try priv.signPSS(message: msg, kind: kind)
            XCTAssertTrue(pub.verifyPSS(signature: sig2, message: msg, kind: kind))
        } catch RSA.Exception.sign {
            let md = MessageDigest(kind)
            XCTAssertTrue(priv.n.magnitude.count * 8 < 2 * md.digestLength + 2)
        }
    }

    func test1() throws {
        try doTest1(1024)
        try doTest1(2048)
        try doTest1(3072)
        try doTest1(4096)
    }
    
    func test2() throws {
        var size = 1088
        for _ in 0 ..< 10 {
            try doTest1(size)
            size += 64
        }
    }


}
