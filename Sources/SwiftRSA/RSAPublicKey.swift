//
//  RSAPublicKey.swift
//  SwiftRSATest
//
//  Created by Leif Ibsen on 01/02/2022.
//

import Foundation
import BigInt
import ASN1
import Digest

/// The public key
public class RSAPublicKey: CustomStringConvertible {

    init(_ n: BInt, _ e: BInt) {
        self.n = n
        self.e = e
    }
    

    // MARK: Initializers

    /// Creates a public key from its DER encoding - X509 format or PKCS#8 format
    ///
    /// - Parameters:
    ///   - der: The DER encoding of the key
    ///   - format: The key format
    /// - Throws: An exception if the DER encoding is wrong
    public convenience init(der: Bytes, format: RSA.KeyFormat) throws {
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw RSA.Exception.asn1Structure
        }
        if seq.getValue().count != 2 {
            throw RSA.Exception.asn1Structure
        }
        switch format {
        case .X509:
            guard let n = seq.get(0) as? ASN1Integer, let e = seq.get(1) as? ASN1Integer else {
                throw RSA.Exception.asn1Structure
            }
            if n.value.bitWidth & 0x3f != 0 {
                throw RSA.Exception.asn1Structure
            }
            self.init(n.value, e.value)
        case .PKCS8:
            guard let seq1 = seq.get(0) as? ASN1Sequence, let bits = seq.get(1) as? ASN1BitString  else {
                throw RSA.Exception.asn1Structure
            }
            if seq1.getValue().count != 2 {
                throw RSA.Exception.asn1Structure
            }
            guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
                throw RSA.Exception.asn1Structure
            }
            guard let _ = seq1.get(1) as? ASN1Null else {
                throw RSA.Exception.asn1Structure
            }
            if oid != RSA.OID {
                throw RSA.Exception.asn1Structure
            }
            if bits.unused > 0 {
                throw RSA.Exception.asn1Structure
            }
            let asn1x = try ASN1.build(bits.bits)
            guard let seq2 = asn1x as? ASN1Sequence else {
                throw RSA.Exception.asn1Structure
            }
            if seq2.getValue().count != 2 {
                throw RSA.Exception.asn1Structure
            }
            guard let n = seq2.get(0) as? ASN1Integer, let e = seq2.get(1) as? ASN1Integer else {
                throw RSA.Exception.asn1Structure
            }
            if n.value.bitWidth & 0x3f != 0 {
                throw RSA.Exception.asn1Structure
            }
            self.init(n.value, e.value)
        }
    }

    /// Creates a public key from its PEM encoding - X509 format or PKCS#8 format
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    ///   - format: The key format
    /// - Throws: An exception if the PEM encoding is wrong
    public convenience init(pem: String, format: RSA.KeyFormat) throws {
        switch format {
        case .X509:
            try self.init(der: Base64.pemDecode(pem, "RSA PUBLIC KEY"), format: .X509)
        case .PKCS8:
            try self.init(der: Base64.pemDecode(pem, "PUBLIC KEY"), format: .PKCS8)
        }
    }


    // MARK: Stored Properties
    
    /// The modulus
    public let n: BInt
    /// The public exponent
    public let e: BInt

    
    // MARK: Computed Properties

    /// ASN1 representation of `self`
    public var description: String { get { return ASN1Sequence().add(ASN1Integer(self.n)).add(ASN1Integer(self.e)).description } }


    // MARK: Instance Methods

    /// Get the DER encoded ASN1 representation of `self` in *X509* or *PKCS#8* format
    ///
    /// - Parameters:
    ///   - format: X509 or PKCS#8 format
    /// - Returns: The DER encoded ASN1 representation of `self`
    public func derEncoded(format: RSA.KeyFormat) -> Bytes {
        let pubKey = ASN1Sequence().add(ASN1Integer(self.n)).add(ASN1Integer(self.e))
        switch format {
        case .X509:
            return pubKey.encode()
        case .PKCS8:
            do {
                let seq1 = ASN1Sequence().add(RSA.OID).add(ASN1.NULL)
                let bits = try ASN1BitString(pubKey.encode(), 0)
                return ASN1Sequence().add(seq1).add(bits).encode()
            } catch {
                // Can't happen
                fatalError("asn1Encoded")
            }
        }
    }

    /// Get the PEM encoded representation of `self` in *X509* or *PKCS#8* format
    ///
    /// - Parameters:
    ///   - format: X509 or PKCS#8 format
    /// - Returns: The PEM encoded representation of `self`
    public func pemEncoded(format: RSA.KeyFormat) -> String {
        let der = self.derEncoded(format: format)
        switch format {
        case .X509:
            return Base64.pemEncode(der, "RSA PUBLIC KEY")
        case .PKCS8:
            return Base64.pemEncode(der, "PUBLIC KEY")
        }
    }

    /// Encrypts a byte array using the PKCS1 scheme
    ///
    /// - Parameters:
    ///   - message: The bytes to encrypt
    /// - Returns: The encrypted message
    /// - Throws: A `encrypt` exception if encryption fails
    public func encryptPKCS1(message: Bytes) throws -> Bytes {
        // [PKCS1] - section 7.2.1
        let k = self.n.magnitude.count * 8
        let mLen = message.count
        if mLen > k - 11 {
            throw RSA.Exception.encrypt(size: k - 11)
        }
        var EM = Bytes(repeating: 0, count: k)
        EM[1] = 2
        guard SecRandomCopyBytes(kSecRandomDefault, k - 3 - mLen, &EM[2]) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
        for i in 2 ..< k - mLen - 1 {
            if EM[i] == 0 {
                EM[i] = 1
            }
        }
        for i in 0 ..< mLen {
            EM[k - mLen + i] = message[i]
        }
        return RSA.I2OSP(RSA.OS2IP(EM).expMod(self.e, self.n), k)
    }
    
    /// Verifies a signature using the PKCS1 scheme
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - message: The message to verify the signature for
    ///   - kind: The message digest kind to use
    /// - Returns: `true` if the signature is verified, `false` otherwise
    public func verifyPKCS1(signature: Bytes, message: Bytes, kind: MessageDigest.Kind) -> Bool {
        // [PKCS1] - section 8.2.2
        let k = self.n.magnitude.count * 8
        if signature.count != k {
            return false
        }
        let md = MessageDigest(kind)
        md.update(message)
        let h = md.digest()
        var EM: Bytes = [0, 1]
        let di = RSA.digestInfo(kind)
        for _ in 0 ..< k - h.count - di.count - 3 {
            EM.append(0xff)
        }
        EM.append(0)
        EM.append(contentsOf: di)
        EM.append(contentsOf: h)

        let s = RSA.OS2IP(signature)
        let m = s.expMod(self.e, self.n)
        let EM1 = RSA.I2OSP(m, k)
        return EM == EM1
    }

    /// Encrypts a byte array using the OAEP scheme
    ///
    /// - Parameters:
    ///   - message: The bytes to encrypt
    ///   - kind: The message digest kind to use
    ///   - label: An optional label - default is an empty array
    /// - Returns: The encrypted message
    /// - Throws: A `encrypt` exception if encryption fails
    public func encryptOAEP(message: Bytes, kind: MessageDigest.Kind, label: Bytes = []) throws -> Bytes {
        // [PKCS1] - section 7.1.1
        let k = self.n.magnitude.count * 8
        let mLen = message.count
        let md = MessageDigest(kind)
        let hLen = md.digestLength
        if mLen > k - 2 * hLen - 2 {
            throw RSA.Exception.encrypt(size: k - 2 * hLen - 2)
        }
        md.update(label)
        let lHash = md.digest()
        let PS = Bytes(repeating: 0, count: k - mLen - 2 * hLen - 2)
        let DB = lHash + PS + [1] + message
        var seed = Bytes(repeating: 0, count: hLen)
        guard SecRandomCopyBytes(kSecRandomDefault, hLen, &seed) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
        let dbMask = KDF.MGF1(kind, seed, k - hLen - 1)
        var maskedDB = DB
        for i in 0 ..< maskedDB.count {
            maskedDB[i] ^= dbMask[i]
        }
        let seedMask = KDF.MGF1(kind, maskedDB, hLen)
        var maskedSeed = seed
        for i in 0 ..< maskedSeed.count {
            maskedSeed[i] ^= seedMask[i]
        }
        let EM: Bytes = [0] + maskedSeed + maskedDB
        assert(EM.count == k)
        let m = RSA.OS2IP(EM)
        let c = m.expMod(self.e, self.n)
        return RSA.I2OSP(c, k)
    }

    /// Verifies a signature using the PSS scheme
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - message: The message to verify the signature for
    ///   - kind: The message digest kind to use
    /// - Returns: `true` if the signature is verified, `false` otherwise
    public func verifyPSS(signature: Bytes, message: Bytes, kind: MessageDigest.Kind) -> Bool {
        // [PKCS1] - section 8.1.2
        let k = self.n.magnitude.count * 8
        if signature.count != k {
            return false
        }
        let s = RSA.OS2IP(signature)
        let m = s.expMod(self.e, self.n)
        let EM = RSA.I2OSP(m, k)
        return PSSVerify(message, EM, k, kind)
    }

    func PSSVerify(_ message: Bytes, _ EM: Bytes, _ k: Int, _ kind: MessageDigest.Kind) -> Bool {
        let md = MessageDigest(kind)
        let hLen = md.digestLength
        if k < 2 * hLen + 2 {
            return false
        }
        md.update(message)
        let mHash = md.digest()
        if EM[k - 1] != 0xbc {
            return false
        }
        let maskedDB = EM[0 ..< k - hLen - 1]
        let H = Bytes(EM[k - hLen - 1 ..< k - 1])
        if maskedDB[0] >> 7 != 0 {
            return false
        }
        let dbMask = KDF.MGF1(kind, H, k - hLen - 1)
        var DB = maskedDB
        for i in 0 ..< DB.count {
            DB[i] ^= dbMask[i]
        }
        DB[0] <<= 1
        DB[0] >>= 1
        for i in 0 ..< k - 2 * hLen - 2 {
            if DB[i] != 0 {
                return false
            }
        }
        if DB[k - 2 * hLen - 2] != 1 {
            return false
        }
        let salt = DB[DB.count - hLen ..< DB.count]
        let M1 = Bytes(repeating: 0, count: 8) + mHash + salt
        md.update(M1)
        let H1 = md.digest()
        return H == H1
    }

}
