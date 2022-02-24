//
//  PemTest.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 08/02/2022.
//

import XCTest

class PemTest: XCTestCase {

    func test1() throws {
        let (pubKey, privKey) = try RSA.makeKeyPair(size: 1024, exponent: RSA.F4)
        let pubPemX509 = pubKey.pemEncoded(format: .X509)
        let privPemX509 = privKey.pemEncoded(format: .X509)
        let pubPemPKCS8 = pubKey.pemEncoded(format: .PKCS8)
        let privPemPKCS8 = privKey.pemEncoded(format: .PKCS8)
        let pubKey1 = try RSAPublicKey(pem: pubPemX509, format: .X509)
        let privKey1 = try RSAPrivateKey(pem: privPemX509, format: .X509)
        XCTAssertEqual(pubKey.n, pubKey1.n)
        XCTAssertEqual(pubKey.e, pubKey1.e)
        XCTAssertEqual(privKey.n, privKey1.n)
        XCTAssertEqual(privKey.e, privKey1.e)
        XCTAssertEqual(privKey.d, privKey1.d)
        XCTAssertEqual(privKey.p, privKey1.p)
        XCTAssertEqual(privKey.q, privKey1.q)
        XCTAssertEqual(privKey.dP, privKey1.dP)
        XCTAssertEqual(privKey.dQ, privKey1.dQ)
        XCTAssertEqual(privKey.qInv, privKey1.qInv)
        let pubKey2 = try RSAPublicKey(pem: pubPemPKCS8, format: .PKCS8)
        let privKey2 = try RSAPrivateKey(pem: privPemPKCS8, format: .PKCS8)
        XCTAssertEqual(pubKey.n, pubKey2.n)
        XCTAssertEqual(pubKey.e, pubKey2.e)
        XCTAssertEqual(privKey.n, privKey2.n)
        XCTAssertEqual(privKey.e, privKey2.e)
        XCTAssertEqual(privKey.d, privKey2.d)
        XCTAssertEqual(privKey.p, privKey2.p)
        XCTAssertEqual(privKey.q, privKey2.q)
        XCTAssertEqual(privKey.dP, privKey2.dP)
        XCTAssertEqual(privKey.dQ, privKey2.dQ)
        XCTAssertEqual(privKey.qInv, privKey2.qInv)
    }

    func test2() throws {
        let (pubKey, privKey) = try RSA.makeKeyPair(size: 1024, exponent: RSA.F4)
        let pubDerX509 = pubKey.derEncoded(format: .X509)
        let privDerX509 = privKey.derEncoded(format: .X509)
        let pubDerPKCS8 = pubKey.derEncoded(format: .PKCS8)
        let privDerPKCS8 = privKey.derEncoded(format: .PKCS8)
        let pubKey1 = try RSAPublicKey(der: pubDerX509, format: .X509)
        let privKey1 = try RSAPrivateKey(der: privDerX509, format: .X509)
        XCTAssertEqual(pubKey.n, pubKey1.n)
        XCTAssertEqual(pubKey.e, pubKey1.e)
        XCTAssertEqual(privKey.n, privKey1.n)
        XCTAssertEqual(privKey.e, privKey1.e)
        XCTAssertEqual(privKey.d, privKey1.d)
        XCTAssertEqual(privKey.p, privKey1.p)
        XCTAssertEqual(privKey.q, privKey1.q)
        XCTAssertEqual(privKey.dP, privKey1.dP)
        XCTAssertEqual(privKey.dQ, privKey1.dQ)
        XCTAssertEqual(privKey.qInv, privKey1.qInv)
        let pubKey2 = try RSAPublicKey(der: pubDerPKCS8, format: .PKCS8)
        let privKey2 = try RSAPrivateKey(der: privDerPKCS8, format: .PKCS8)
        XCTAssertEqual(pubKey.n, pubKey2.n)
        XCTAssertEqual(pubKey.e, pubKey2.e)
        XCTAssertEqual(privKey.n, privKey2.n)
        XCTAssertEqual(privKey.e, privKey2.e)
        XCTAssertEqual(privKey.d, privKey2.d)
        XCTAssertEqual(privKey.p, privKey2.p)
        XCTAssertEqual(privKey.q, privKey2.q)
        XCTAssertEqual(privKey.dP, privKey2.dP)
        XCTAssertEqual(privKey.dQ, privKey2.dQ)
        XCTAssertEqual(privKey.qInv, privKey2.qInv)
    }

}
