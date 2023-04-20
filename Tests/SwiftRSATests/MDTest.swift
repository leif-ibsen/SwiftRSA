//
//  MDTest.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 11/02/2022.
//

import XCTest
@testable import SwiftRSA

// Test vectors from http://www.di-mgt.com.au/sha_testvectors.html
class MDTest: XCTestCase {

    let s1 = Bytes("".utf8)
    let s2 = Bytes("abc".utf8)
    let s3 = Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
    let s4 = Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".utf8)
    let s5 = Bytes(repeating: 0x61, count: 1000000)

    func toHexString(_ x: Bytes) -> String {
        let hexDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
        var s = ""
        for b in x {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0xf)])
        }
        return s
    }

    func test1() {
        let md = MessageDigest(.SHA1)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "a9993e364706816aba3e25717850c26c9cd0d89d")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "a49b2446a02c645bf419f995b67091253a04a259")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f")
    }

    func test2_224() {
        let md = MessageDigest(.SHA2_224)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67")
    }

    func test2_256() {
        let md = MessageDigest(.SHA2_256)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    func test2_384() {
        let md = MessageDigest(.SHA2_384)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985")
    }

    func test2_512() {
        let md = MessageDigest(.SHA2_512)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")
    }

    func test3_224() {
        let md = MessageDigest(.SHA3_224)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c")
    }

    func test3_256() {
        let md = MessageDigest(.SHA3_256)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1")
    }

    func test3_384() {
        let md = MessageDigest(.SHA3_384)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340")
    }

    func test3_512() {
        let md = MessageDigest(.SHA3_512)
        md.update(s1)
        XCTAssertEqual(toHexString(md.digest()), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")
        md.update(s2)
        XCTAssertEqual(toHexString(md.digest()), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
        md.update(s3)
        XCTAssertEqual(toHexString(md.digest()), "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e")
        md.update(s4)
        XCTAssertEqual(toHexString(md.digest()), "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185")
        md.update(s5)
        XCTAssertEqual(toHexString(md.digest()), "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87")
    }
}
