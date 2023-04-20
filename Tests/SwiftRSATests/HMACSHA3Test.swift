//
//  HMACSHA3Test.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 26/02/2022.
//

import XCTest
@testable import SwiftRSA

// Test vectors from https://fossies.org
class HMACSHA3Test: XCTestCase {

    let key1 = Utilities.hex2bytes(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    let data1 = Utilities.hex2bytes(
        "4869205468657265")
    let hmac1_224 = Utilities.hex2bytes(
        "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7")
    let hmac1_256 = Utilities.hex2bytes(
        "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb")
    let hmac1_384 = Utilities.hex2bytes(
        "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd")
    let hmac1_512 = Utilities.hex2bytes(
        "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e")
    let key2 = Utilities.hex2bytes(
        "4a656665")
    let data2 = Utilities.hex2bytes(
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f")
    let hmac2_224 = Utilities.hex2bytes(
        "7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66")
    let hmac2_256 = Utilities.hex2bytes(
        "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5")
    let hmac2_384 = Utilities.hex2bytes(
        "f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a")
    let hmac2_512 = Utilities.hex2bytes(
        "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024")
    let key3 = Utilities.hex2bytes(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let data3 = Utilities.hex2bytes(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
    let hmac3_224 = Utilities.hex2bytes(
        "676cfc7d16153638780390692be142d2df7ce924b909c0c08dbfdc1a")
    let hmac3_256 = Utilities.hex2bytes(
        "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207")
    let hmac3_384 = Utilities.hex2bytes(
        "275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373b41b6ab5bf174bec422e53fc3135ac6e")
    let hmac3_512 = Utilities.hex2bytes(
        "309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03")
    let key4 = Utilities.hex2bytes(
        "0102030405060708090a0b0c0d0e0f10111213141516171819")
    let data4 = Utilities.hex2bytes(
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
    let hmac4_224 = Utilities.hex2bytes(
        "a9d7685a19c4e0dbd9df2556cc8a7d2a7733b67625ce594c78270eeb")
    let hmac4_256 = Utilities.hex2bytes(
        "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7")
    let hmac4_384 = Utilities.hex2bytes(
        "3a5d7a879702c086bc96d1dd8aa15d9c46446b95521311c606fdc4e308f4b984da2d0f9449b3ba8425ec7fb8c31bc136")
    let hmac4_512 = Utilities.hex2bytes(
        "b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d")
    let key5 = Utilities.hex2bytes(
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
    let data5 = Utilities.hex2bytes(
        "546573742057697468205472756e636174696f6e")
    let hmac5_224 = Utilities.hex2bytes(
        "49fdd3abd005ebb8ae63fea946d1883c")
    let hmac5_256 = Utilities.hex2bytes(
        "6e02c64537fb118057abb7fb66a23b3c")
    let hmac5_384 = Utilities.hex2bytes(
        "47c51ace1ffacffd7494724682615783")
    let hmac5_512 = Utilities.hex2bytes(
        "0fa7475948f43f48ca0516671e18978c")
    let key6 = Utilities.hex2bytes(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let data6 = Utilities.hex2bytes(
        "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374")
    let hmac6_224 = Utilities.hex2bytes(
        "b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f")
    let hmac6_256 = Utilities.hex2bytes(
        "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b")
    let hmac6_384 = Utilities.hex2bytes(
        "0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb9616fd669138d33a1105e07c72b6953bcc")
    let hmac6_512 = Utilities.hex2bytes(
        "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4")
    let key7 = Utilities.hex2bytes(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let data7 = Utilities.hex2bytes(
        "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e")
    let hmac7_224 = Utilities.hex2bytes(
        "05d8cd6d00faea8d1eb68ade28730bbd3cbab6929f0a086b29cd62a0")
    let hmac7_256 = Utilities.hex2bytes(
        "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123")
    let hmac7_384 = Utilities.hex2bytes(
        "026fdf6b50741e373899c9f7d5406d4eb09fc6665636fc1a530029ddf5cf3ca5a900edce01f5f61e2f408cdf2fd3e7e8")
    let hmac7_512 = Utilities.hex2bytes(
        "38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba")

    func test224() {
        let hmac = HMAC(.SHA3_224)
        XCTAssertEqual(hmac1_224, hmac.hmac(key1, data1))
        XCTAssertEqual(hmac2_224, hmac.hmac(key2, data2))
        XCTAssertEqual(hmac3_224, hmac.hmac(key3, data3))
        XCTAssertEqual(hmac4_224, hmac.hmac(key4, data4))
        XCTAssertEqual(hmac5_224, Bytes(hmac.hmac(key5, data5)[0 ..< 16]))
        XCTAssertEqual(hmac6_224, hmac.hmac(key6, data6))
        XCTAssertEqual(hmac7_224, hmac.hmac(key7, data7))
    }

    func test256() {
        let hmac = HMAC(.SHA3_256)
        XCTAssertEqual(hmac1_256, hmac.hmac(key1, data1))
        XCTAssertEqual(hmac2_256, hmac.hmac(key2, data2))
        XCTAssertEqual(hmac3_256, hmac.hmac(key3, data3))
        XCTAssertEqual(hmac4_256, hmac.hmac(key4, data4))
        XCTAssertEqual(hmac5_256, Bytes(hmac.hmac(key5, data5)[0 ..< 16]))
        XCTAssertEqual(hmac6_256, hmac.hmac(key6, data6))
        XCTAssertEqual(hmac7_256, hmac.hmac(key7, data7))
    }

    func test384() {
        let hmac = HMAC(.SHA3_384)
        XCTAssertEqual(hmac1_384, hmac.hmac(key1, data1))
        XCTAssertEqual(hmac2_384, hmac.hmac(key2, data2))
        XCTAssertEqual(hmac3_384, hmac.hmac(key3, data3))
        XCTAssertEqual(hmac4_384, hmac.hmac(key4, data4))
        XCTAssertEqual(hmac5_384, Bytes(hmac.hmac(key5, data5)[0 ..< 16]))
        XCTAssertEqual(hmac6_384, hmac.hmac(key6, data6))
        XCTAssertEqual(hmac7_384, hmac.hmac(key7, data7))
    }

    func test512() {
        let hmac = HMAC(.SHA3_512)
        XCTAssertEqual(hmac1_512, hmac.hmac(key1, data1))
        XCTAssertEqual(hmac2_512, hmac.hmac(key2, data2))
        XCTAssertEqual(hmac3_512, hmac.hmac(key3, data3))
        XCTAssertEqual(hmac4_512, hmac.hmac(key4, data4))
        XCTAssertEqual(hmac5_512, Bytes(hmac.hmac(key5, data5)[0 ..< 16]))
        XCTAssertEqual(hmac6_512, hmac.hmac(key6, data6))
        XCTAssertEqual(hmac7_512, hmac.hmac(key7, data7))
    }

}
