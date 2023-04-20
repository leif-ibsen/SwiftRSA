//
//  ExceptionTest.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 14/02/2022.
//

import XCTest
@testable import SwiftRSA

class ExceptionTest: XCTestCase {

    func testKeyPairParameters() {
        do {
            let (_, _) = try RSA.makeKeyPair(size: 1024, expWidth: 16)
            XCTFail("Expected keyPairParameters exception")
        } catch RSA.Exception.makeKeyPairParameters {
        } catch {
            XCTFail("Expected makeKeyPairParameters exception")
        }
        do {
            let (_, _) = try RSA.makeKeyPair(size: 1024, expWidth: 257)
            XCTFail("Expected keyPairParameters exception")
        } catch RSA.Exception.makeKeyPairParameters {
        } catch {
            XCTFail("Expected makeKeyPairParameters exception")
        }
        do {
            let (_, _) = try RSA.makeKeyPair(size: 1025, expWidth: 17)
            XCTFail("Expected keyPairParameters exception")
        } catch RSA.Exception.makeKeyPairParameters {
        } catch {
            XCTFail("Expected makeKeyPairParameters exception")
        }
    }
    
    func testSign() {
        do {
            let (_, priv) = try RSA.makeKeyPair(size: 1024, exponent: RSA.F4)
            let _ = try priv.signPSS(message: [1, 2, 3], mda: .SHA2_512)
            XCTFail("Expected sign exception")
        } catch RSA.Exception.sign {
        } catch {
            XCTFail("Expected sign exception")
        }
    }

    func testEncrypt() {
        do {
            let b = Bytes(repeating: 1, count: 182)
            let (pub, _) = try RSA.makeKeyPair(size: 1536, exponent: RSA.F4)
            let _ = try pub.encryptPKCS1(message: b)
            XCTFail("Expected encrypt exception")
        } catch RSA.Exception.encrypt {
        } catch {
            XCTFail("Expected encrypt exception")
        }
    }

    func testDecrypt() {
        do {
            let b = Bytes(repeating: 1, count: 93)
            let (_, priv) = try RSA.makeKeyPair(size: 1536, exponent: RSA.F4)
            let _ = try priv.decryptPKCS1(cipher: b)
            XCTFail("Expected decrypt exception")
        } catch RSA.Exception.decrypt {
        } catch {
            XCTFail("Expected decrypt exception")
        }
    }

}
