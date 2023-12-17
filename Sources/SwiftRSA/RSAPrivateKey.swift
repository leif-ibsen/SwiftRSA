//
//  RSAPrivateKey.swift
//  SwiftRSATest
//
//  Created by Leif Ibsen on 01/02/2022.
//

import Foundation
import BigInt
import ASN1
import Digest

///
/// An RSA private key
///
public class RSAPrivateKey: CustomStringConvertible {

    init(_ p: BInt, _ q: BInt, _ e: BInt, _ d: BInt) {
        self.p = p
        self.q = q
        self.e = e
        self.d = d
        self.qInv = q.modInverse(p)
        self.n = p * q
        self.dP = d.mod(p - 1)
        self.dQ = d.mod(q - 1)
    }
    
    static func extract(_ seq: ASN1Sequence, _ px: inout BInt, _ qx: inout BInt, _ ex: inout BInt, _ dx: inout BInt) throws {
        guard let z2 = seq.get(0) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        if z2.value.isNotZero {
            throw RSA.Exception.asn1Structure
        }
        guard let n = seq.get(1) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        guard let e = seq.get(2) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        guard let d = seq.get(3) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        guard let p = seq.get(4) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        guard let q = seq.get(5) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        guard let dP = seq.get(6) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        guard let dQ = seq.get(7) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        guard let qInv = seq.get(8) as? ASN1Integer else {
            throw RSA.Exception.asn1Structure
        }
        if n.value != p.value * q.value {
            throw RSA.Exception.asn1Structure
        }
        if dP.value != d.value.mod(p.value - 1) {
            throw RSA.Exception.asn1Structure
        }
        if dQ.value != d.value.mod(q.value - 1) {
            throw RSA.Exception.asn1Structure
        }
        if qInv.value != q.value.modInverse(p.value) {
            throw RSA.Exception.asn1Structure
        }
        let f = (p.value - 1) * (q.value - 1)
        let f1 = (p.value - 1).lcm(q.value - 1)
        if d.value != e.value.modInverse(f) && d.value != e.value.modInverse(f1) {
            throw RSA.Exception.asn1Structure
        }
        px = p.value
        qx = q.value
        ex = e.value
        dx = d.value
    }


    // MARK: Initializers

    /// Creates a private key from its DER encoding - X509 format or PKCS#8 format
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
        var p = BInt.ZERO
        var q = BInt.ZERO
        var e = BInt.ZERO
        var d = BInt.ZERO
        switch format {
        case .PKCS8:
            guard seq.getValue().count == 3 else {
                throw RSA.Exception.asn1Structure
            }
            guard let z = seq.get(0) as? ASN1Integer else {
                throw RSA.Exception.asn1Structure
            }
            if z.value.isNotZero {
                throw RSA.Exception.asn1Structure
            }
            guard let seq1 = seq.get(1) as? ASN1Sequence else {
                throw RSA.Exception.asn1Structure
            }
            if seq1.getValue().count != 2 {
                throw RSA.Exception.asn1Structure
            }
            guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
                throw RSA.Exception.asn1Structure
            }
            if oid != RSA.OID {
                throw RSA.Exception.asn1Structure
            }
            guard let _ = seq1.get(1) as? ASN1Null else {
                throw RSA.Exception.asn1Structure
            }
            guard let str = seq.get(2) as? ASN1OctetString else {
                throw RSA.Exception.asn1Structure
            }
            let asn2 = try ASN1.build(str.value)
            guard let seq2 = asn2 as? ASN1Sequence else {
                throw RSA.Exception.asn1Structure
            }
            if seq2.getValue().count != 9 {
                throw RSA.Exception.asn1Structure
            }
            try RSAPrivateKey.extract(seq2, &p, &q, &e, &d)
        case .X509:
            guard seq.getValue().count == 9 else {
                throw RSA.Exception.asn1Structure
            }
            try RSAPrivateKey.extract(seq, &p, &q, &e, &d)
        }
        if (p * q).bitWidth & 0x3f != 0 {
            throw RSA.Exception.asn1Structure
        }
        self.init(p, q, e, d)
    }

    /// Creates a private key from its PEM encoding - X509 format or PKCS#8 format
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    ///   - format: The key format
    /// - Throws: An exception if the PEM encoding is wrong
    public convenience init(pem: String, format: RSA.KeyFormat) throws {
        switch format {
        case .X509:
            try self.init(der: Base64.pemDecode(pem, "RSA PRIVATE KEY"), format: .X509)
        case .PKCS8:
            try self.init(der: Base64.pemDecode(pem, "PRIVATE KEY"), format: .PKCS8)
        }
    }

    
    // MARK: Stored Properties

    /// The modulus
    public let n: BInt
    /// The public exponent
    public let e: BInt
    /// The private exponent
    public let d: BInt
    /// The p primefactor
    public let p: BInt
    /// The q primefactor
    public let q: BInt
    /// The p CRT exponent
    public let dP: BInt
    /// The q CRT exponent
    public let dQ: BInt
    /// The CRT coefficient
    public let qInv: BInt


    // MARK: Computed Properties

    /// The public key corresponding to *self*
    public var publicKey: RSAPublicKey { get { return RSAPublicKey(self.n, self.e) } }
    /// An ASN1 representation of *self*
    public var description: String { get { return ASN1Sequence()
            .add(ASN1.ZERO)
            .add(ASN1Integer(self.n))
            .add(ASN1Integer(self.e))
            .add(ASN1Integer(self.d))
            .add(ASN1Integer(self.p))
            .add(ASN1Integer(self.q))
            .add(ASN1Integer(self.dP))
            .add(ASN1Integer(self.dQ))
            .add(ASN1Integer(self.qInv)).description } }

    
    // MARK: Instance Methods

    /// Get the DER encoded ASN1 representation of *self* in *X509* or *PKCS#8* format
    ///
    /// - Parameters:
    ///   - format: X509 or PKCS#8 format
    /// - Returns: The DER encoded ASN1 representation of *self*
    public func derEncoded(format: RSA.KeyFormat) -> Bytes {
        let privKey = ASN1Sequence()
            .add(ASN1.ZERO)
            .add(ASN1Integer(self.n))
            .add(ASN1Integer(self.e))
            .add(ASN1Integer(self.d))
            .add(ASN1Integer(self.p))
            .add(ASN1Integer(self.q))
            .add(ASN1Integer(self.dP))
            .add(ASN1Integer(self.dQ))
            .add(ASN1Integer(self.qInv))
        switch format {
        case .X509:
            return privKey.encode()
        case .PKCS8:
            let seq1 = ASN1Sequence().add(RSA.OID).add(ASN1.NULL)
            let bytes = ASN1OctetString(privKey.encode())
            return ASN1Sequence().add(ASN1.ZERO).add(seq1).add(bytes).encode()
        }
    }

    /// Get the PEM encoded representation of *self* in *X509* or *PKCS#8* format
    ///
    /// - Parameters:
    ///   - format: X509 or PKCS#8 format
    /// - Returns: The PEM encoded representation of *self*
    public func pemEncoded(format: RSA.KeyFormat) -> String {
        let der = self.derEncoded(format: format)
        switch format {
        case .X509:
            return Base64.pemEncode(der, "RSA PRIVATE KEY")
        case .PKCS8:
            return Base64.pemEncode(der, "PRIVATE KEY")
        }
    }

    /// Decrypts a byte array using the PKCS1 scheme
    ///
    /// - Parameters:
    ///   - cipher: The bytes to decrypt
    /// - Returns: The decrypted message
    /// - Throws: A *decryption* exception if decryption fails
    public func decryptPKCS1(cipher: Bytes) throws -> Bytes {
        // [PKCS1] - section 7.2.2
        let k = self.n.magnitude.count * 8
        let mLen = cipher.count
        if mLen != k {
            throw RSA.Exception.decrypt(size: k)
        }
        let c = RSA.OS2IP(cipher)
        let m = RSASDP(c)
        let EM = RSA.I2OSP(m, k)
        if EM[0] != 0 || EM[1] != 2 {
            throw RSA.Exception.decrypt()
        }
        var i = 2
        while i < EM.count && EM[i] != 0 {
            i += 1
        }
        if i < 10 || i == EM.count || EM[i] != 0 {
            throw RSA.Exception.decrypt()
        }
        return Bytes(EM[i + 1 ..< EM.count])
    }

    /// Signs a message using the PKCS1 scheme
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - kind: The message digest kind to use
    /// - Returns: The signature
    /// - Throws: A *sign* exception if signing fails
    public func signPKCS1(message: Bytes, kind: MessageDigest.Kind) throws -> Bytes {
        // [PKCS1] - section 8.2.1
        let k = self.n.magnitude.count * 8
        let md = MessageDigest(kind)
        let di = RSA.digestInfo(kind)
        if k < di.count + md.digestLength + 11 {
            throw RSA.Exception.sign(size: (di.count + md.digestLength + 11) * 8)
        }
        md.update(message)
        let h = md.digest()
        var EM: Bytes = [0, 1]
        for _ in 0 ..< k - h.count - di.count - 3 {
            EM.append(0xff)
        }
        EM.append(0)
        EM.append(contentsOf:di)
        EM.append(contentsOf: h)
        let m = RSA.OS2IP(EM)
        let s = RSASDP(m)
        return RSA.I2OSP(s, k)
    }

    /// Decrypts a byte array using the OAEP scheme
    ///
    /// - Parameters:
    ///   - cipher: The bytes to decrypt
    ///   - kind: The message digest kind to use
    ///   - label: An optional label - default is an empty array
    /// - Returns: The decrypted message
    /// - Throws: A *decryption* exception if decryption fails
    public func decryptOAEP(cipher: Bytes, kind: MessageDigest.Kind, label: Bytes = []) throws -> Bytes {
        // [PKCS1] - section 7.1.2
        let k = self.n.magnitude.count * 8
        let mLen = cipher.count
        if mLen != k {
            throw RSA.Exception.decrypt(size: k)
        }
        let md = MessageDigest(kind)
        let hLen = md.digestLength
        if k < 2 * hLen + 2 {
            throw RSA.Exception.decrypt()
        }
        let c = RSA.OS2IP(cipher)
        let m = RSASDP(c)
        let EM = RSA.I2OSP(m, k)
        md.update(label)
        let lHash = md.digest()
        if EM[0] != 0 {
            throw RSA.Exception.decrypt()
        }
        let maskedSeed = Bytes(EM[1 ... hLen])
        let maskedDB = Bytes(EM[hLen + 1 ..< EM.count])
        let seedMask = KDF.MGF1(kind, maskedDB, hLen)
        var seed = maskedSeed
        for i in 0 ..< seed.count {
            seed[i] ^= seedMask[i]
        }
        let dbMask = KDF.MGF1(kind, seed, k - hLen - 1)
        var DB = maskedDB
        for i in 0 ..< DB.count {
            DB[i] ^= dbMask[i]
        }
        if Bytes(DB[0 ..< hLen]) != lHash {
            throw RSA.Exception.decrypt()
        }
        var i = hLen
        while i < DB.count && DB[i] == 0 {
            i += 1
        }
        if i == DB.count || DB[i] != 1 {
            throw RSA.Exception.decrypt()
        }
        return Bytes(DB[i + 1 ..< DB.count])
    }
    
    /// Signs a message using the PSS scheme
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - kind: The message digest kind to use
    /// - Returns: The signature
    /// - Throws: A *sign* exception if signing fails
    public func signPSS(message: Bytes, kind: MessageDigest.Kind) throws -> Bytes {
        // [PKCS1] - section 8.1.1
        let k = self.n.magnitude.count * 8
        let md = MessageDigest(kind)
        md.update(message)
        let hLen = md.digestLength
        if k < 2 * hLen + 2 {
            throw RSA.Exception.sign(size: (2 * hLen + 2) * 8)
        }
        let mHash = md.digest()
        var salt = Bytes(repeating: 0, count: hLen)
        guard SecRandomCopyBytes(kSecRandomDefault, hLen, &salt) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
        let M1 = Bytes(repeating: 0, count: 8) + mHash + salt
        md.update(M1)
        let H = md.digest()
        let PS = Bytes(repeating: 0, count: k - 2 * hLen - 2)
        let DB = PS + [0x01] + salt
        let dbMask = KDF.MGF1(kind, H, k - hLen - 1)
        var maskedDB = DB
        for i in 0 ..< maskedDB.count {
            maskedDB[i] ^= dbMask[i]
        }
        maskedDB[0] <<= 1
        maskedDB[0] >>= 1
        let EM = maskedDB + H + [0xbc]
        return RSA.I2OSP(RSASDP(RSA.OS2IP(EM)), k)
    }

    func RSASDP(_ x: BInt) -> BInt {
        let a1 = x.expMod(self.dP, self.p)
        let a2 = x.expMod(self.dQ, self.q)
        let h = ((a1 - a2) * self.qInv).mod(self.p)
        return (a2 + self.q * h).mod(self.n)
    }
    
}
