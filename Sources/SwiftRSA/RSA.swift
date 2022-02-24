//
//  RSA.swift
//  SwiftRSATest
//
//  Created by Leif Ibsen on 02/02/2022.
//

import ASN1
import BigInt
import OpenGL

///
/// An 8-bit unsigned integer
///
public typealias Byte = UInt8
///
/// An array of 8-bit unsigned integers
///
public typealias Bytes = [Byte]

///
/// There is no RSA instances.
/// RSA exists to provide a namespace. It contains static key pair generation methods
///
public class RSA {
    
    private init() {
        // Not meant to be instantiated
    }

    // [PKCS1] - section 4.2
    static func OS2IP(_ x: Bytes) -> BInt {
        return BInt(magnitude: x)
    }

    // [PKCS1] - section 4.1
    static func I2OSP(_ x: BInt, _ length: Int) -> Bytes {
        var b = x.asMagnitudeBytes()
        while b.count < length {
            b.insert(0, at: 0)
        }
        return b
    }
    
    // [PKCS1] - appendix B.2.1
    static func mgf1(_ seed: Bytes, _ length: Int, _ mda: MessageDigestAlgorithm) -> Bytes {
        let md = MessageDigest(mda)
        var t: Bytes = []
        var counter: Bytes = [0, 0, 0, 0]
        let n = length == 0 ? 0 : (length - 1) / md.digestLength + 1
        for _ in 0 ..< n {
            md.update(seed)
            md.update(counter)
            let h = md.digest()
            t += h
            counter[3] &+= 1
            if counter[3] == 0 {
                counter[2] &+= 1
                if counter[2] == 0 {
                    counter[1] &+= 1
                    if counter[1] == 0 {
                        counter[0] &+= 1
                    }
                }
            }
        }
        return Bytes(t[0 ..< length])
    }


    // MARK: Static Methods
    
    /// Generates an RSA key pair with a given modulus size
    ///
    /// - Parameters:
    ///   - size: The size of the RSA modulus - at least 1024, divisible by 64
    /// - Returns: The RSA key pair
    public static func makeKeyPair(size: Int) throws -> (RSAPublicKey, RSAPrivateKey) {
        let b = BInt.ONE << 256 - RSA.F4
        var e: BInt
        repeat {
            e = b.randomLessThan() + RSA.F4
        } while e.isEven
        return try makeKeyPair(size: size, exponent: e)
    }

    /*
     * [NIST] - section 6.3.1
     */
    /// Generates an RSA key pair with a given modulus size and public exponent
    ///
    /// - Parameters:
    ///   - size: The size of the RSA modulus - at least 1024, divisible by 64
    ///   - exponent: The public exponent - an odd number in the interval [65537 .. 2^256 - 1]
    /// - Returns: The RSA key pair
    public static func makeKeyPair(size: Int, exponent: BInt) throws -> (RSAPublicKey, RSAPrivateKey) {
        if size < 1024 || size & 0x3f != 0 {
            throw RSA.Exception.makeKeyPairParameters
        }
        if exponent < RSA.F4 || exponent >= BInt.ONE << 256 || exponent.isEven {
            throw RSA.Exception.makeKeyPairParameters
        }
        var p = BInt.ZERO
        var q = BInt.ZERO
        var f = BInt.ZERO
        var n = BInt.ZERO
        let size2 = size / 2
        let diff = BInt.ONE << (size2 - 100)
        while true {
            p = BInt.probablePrime(size2)
            q = BInt.probablePrime(size2)
            n = p * q
            f = (p - 1).lcm(q - 1)
            if n.bitWidth == size && exponent.gcd(f) == 1 && f >= exponent * (BInt.ONE << size2) && (p - q).abs > diff {
                break
            }
        }
        return (RSAPublicKey(n, exponent), RSAPrivateKey(p, q, exponent, exponent.modInverse(f)))
    }

    /*
     * [NIST] - section 6.3.2
     */
    /// Generates an RSA key pair with a given modulus size and public exponent bit width
    ///
    /// - Parameters:
    ///   - size: The size of the RSA modulus - at least 1024, divisible by 64
    ///   - expWidth: The public exponent bit width - a number in the interval [17 .. 256]
    /// - Returns: The RSA key pair
    public static func makeKeyPair(size: Int, expWidth: Int) throws -> (RSAPublicKey, RSAPrivateKey) {
        if expWidth < 17 || expWidth > 256 {
            throw RSA.Exception.makeKeyPairParameters
        }
        let b = BInt.ONE << (expWidth - 1)
        var e: BInt
        repeat {
            e = b.randomLessThan() + b + 1
        } while e.isEven
        return try makeKeyPair(size: size, exponent: e)
    }

    
    // MARK: Enumerations
    
    ///
    /// Key formats
    ///
    public enum KeyFormat {
        /// The X509 key format
        case X509
        /// The PKCS#8 key format
        case PKCS8
    }

    ///
    /// Message digest algorithms
    ///
    public enum MessageDigestAlgorithm: CaseIterable {
        /// The SHA1 message digest
        case SHA1
        /// The SHA2 224 message digest
        case SHA2_224
        /// The SHA2 256 message digest
        case SHA2_256
        /// The SHA2 384 message digest
        case SHA2_384
        /// The SHA2 512 message digest
        case SHA2_512
        /// The SHA3 224 message digest
        case SHA3_224
        /// The SHA3 256 message digest
        case SHA3_256
        /// The SHA3 384 message digest
        case SHA3_384
        /// The SHA3 512 message digest
        case SHA3_512
    }

    ///
    /// RSA exceptions
    ///
    public enum Exception: Error, CustomStringConvertible {
        
        public var description: String {
            switch self {
            case .asn1Structure:
                return "Wrong ASN1 data"
            case .base64:
                return "Base64 decoding error"
            case .decrypt(let size):
                return size == 0 ? "Decryption error" : "Cipher size != \(size) bytes"
            case .encrypt(let size):
                return "Message size > \(size) bytes"
            case .makeKeyPairParameters:
                return "Wrong key pair parameters"
            case .pemStructure:
                return "Wrong PEM data"
            case .sign(let size):
                return "Modulus size < \(size) bit"
            }
        }
        
        /// Wrong ASN1 data
        case asn1Structure
        /// Base64 decoding error
        case base64
        /// Decryption error
        case decrypt(size: Int = 0)
        /// Encryption error
        case encrypt(size: Int)
        /// Wrong key pair parameters
        case makeKeyPairParameters
        /// Wrong PEM data
        case pemStructure
        /// Sign error
        case sign(size: Int)
    }

    
    // MARK: Constants

    /// F4 = 65537
    public static let F4 = BInt.ONE << 16 + BInt.ONE
    
    /// The RSA OID
    public static let OID = ASN1ObjectIdentifier("1.2.840.113549.1.1.1")!

}
