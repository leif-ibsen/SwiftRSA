//
//  MakeKeysTest.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 07/02/2022.
//

import XCTest
import BigInt

class MakeKeysTest: XCTestCase {

    func doTest(_ pub: RSAPublicKey, _ priv: RSAPrivateKey, _ size: Int) {
        XCTAssertEqual(priv.n.bitWidth, size)
        XCTAssertEqual(priv.n, pub.n)
        XCTAssertEqual(priv.e, pub.e)
        XCTAssertEqual(priv.n, priv.p * priv.q)
        XCTAssertTrue(priv.p.isProbablyPrime())
        XCTAssertEqual(priv.p.bitWidth, size / 2)
        XCTAssertTrue(priv.q.isProbablyPrime())
        XCTAssertEqual(priv.q.bitWidth, size / 2)
        let f = (priv.p - 1).lcm(priv.q - 1)
        XCTAssertTrue(priv.d > BInt.ONE << (size / 2))
        XCTAssertEqual(priv.d, priv.e.modInverse(f))
        XCTAssertEqual(priv.qInv, priv.q.modInverse(priv.p))
        XCTAssertEqual(priv.dP, priv.d.mod(priv.p - 1))
        XCTAssertEqual(priv.dQ, priv.d.mod(priv.q - 1))
        XCTAssertEqual(priv.e.gcd(priv.p - 1), BInt.ONE)
        XCTAssertEqual(priv.e.gcd(priv.q - 1), BInt.ONE)
        let pub1 = priv.publicKey
        XCTAssertEqual(pub.n, pub1.n)
        XCTAssertEqual(pub.e, pub1.e)
    }

    func doTest1(_ size: Int, _ exp: BInt) throws {
        let (pub, priv) = try RSA.makeKeyPair(size: size, exponent: exp)
        doTest(pub, priv, size)
    }

    func doTest2(_ size: Int, _ expWidth: Int) throws {
        let (pub, priv) = try RSA.makeKeyPair(size: size, expWidth: expWidth)
        XCTAssertEqual(pub.e.bitWidth, expWidth)
        doTest(pub, priv, size)
    }

    func doTest3(_ size: Int) throws {
        let (pub, priv) = try RSA.makeKeyPair(size: size)
        doTest(pub, priv, size)
    }

    func test1() throws {
        try doTest1(1024, RSA.F4)
        try doTest1(2048, RSA.F4)
        try doTest1(3072, RSA.F4)
        try doTest1(4096, RSA.F4)
        try doTest2(1024, 17)
        try doTest2(2048, 17)
        try doTest2(3072, 17)
        try doTest2(4096, 17)
        try doTest2(1024, 256)
        try doTest2(2048, 256)
        try doTest2(3072, 256)
        try doTest2(4096, 256)
        try doTest3(1024)
        try doTest3(2048)
        try doTest3(3072)
        try doTest3(4096)
    }

    func test2() throws {
        try doTest1(1088, RSA.F4)
        try doTest1(1152, RSA.F4)
        try doTest1(1216, RSA.F4)
        try doTest1(1280, RSA.F4)
        try doTest2(1088, 17)
        try doTest2(1152, 17)
        try doTest2(1216, 17)
        try doTest2(1280, 17)
        try doTest2(1088, 256)
        try doTest2(1152, 256)
        try doTest2(1216, 256)
        try doTest2(1280, 256)
        try doTest3(1088)
        try doTest3(1152)
        try doTest3(1216)
        try doTest3(1280)
    }

}
