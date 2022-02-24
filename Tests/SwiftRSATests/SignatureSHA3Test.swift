//
//  SignatureSHA3Test.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 16/02/2022.
//

import XCTest

// Test vectors from Wycheproof - files
//    rsa_signature_2048_sha3_224_test.json
//    rsa_signature_2048_sha3_256_test.json
//    rsa_signature_2048_sha3_384_test.json
//    rsa_signature_2048_sha3_512_test.json
class SignatureSHA3Test: XCTestCase {

    struct testStruct {
        let msg: String
        let sig: String
        let mda: RSA.MessageDigestAlgorithm
        let ok: Bool
        
        init(msg: String, sig: String, mda: RSA.MessageDigestAlgorithm, ok: Bool = true) {
            self.msg = msg
            self.sig = sig
            self.mda = mda
            self.ok = ok
        }
    }

    let pubPem224_2048 =
"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz194oqel4oUMRErn/zOn
GresOrTKgtGZeT1kGiDb1NnFE0Oc0g4I/edohj8MIcWQQp2vXqzhuOu+1Kq5ifPd
pWDnt2liZfFQ8LUqMv9KBHWUDS5bHmBNOboReKF3LALoCRo4V4d6gETEi6nCEvZ4
yBoXzat+VnjZPf2AgrSo5ZP/nlDRbzGb3ckQVmFTYeyKDG7b7zp5f29a80t5dmHF
NGhwMH+/Q1X8EJUjh14wwhEaLcUr3iHOlHRzsi5EEdhcregxKmtgjpJo+46lGtVx
a9kHyT/mLbMOs4hB4xSFUnTkQftS0+DqV+l3wT6zfq8kvNVizlZb/aE9FzyyfWHe
zwIDAQAB
-----END PUBLIC KEY-----
"""

    let tests224_2048: [testStruct] = [
        testStruct(
            msg: "",
            sig: "228d2614424ad79e157d141455d0ecb4113640f1e53c35cda25d5d847e90c44487272af285ce12b910dbcc2a298479ae0e399839c43851d8cdba3851cd127c30b4bc24c564f75bd492e4b26e971aaa588e81b956784c393cac48f7a5e9310e7c5f902cbc9a62b9b1706c81ae2fa1e04aa6e6e9e99345c448448e407fbe2aef5bb693a096cb81fd745bc9dd063060930512f34a6ab4390a2043acde1ee1e0032dfb1a03e9e64af2668804c31d245cf1005e208cd2e269ed8718af0459ff5d34d9e871fff7e5110deff6b2d3c292256ad63335379338743333c9d19d6ec1f86444c4ad5158406e716194e6a9fc6462b80b539479fc42740b64bffda1bb56739c07",
            mda: .SHA3_224),
        testStruct(
            msg: "0000000000000000000000000000000000000000",
            sig: "509bf60e87b770c763c8992dc765d841e44e6caade4254aa30f09568b8882dddbcab36f8d025e1f25b588d12d0e8d1048e6bf2a98b04b6c8933326379dec498dcf7e1fc01dbfad41c879c9d8c04ae380cce955736206a218738031ef4911164062da5f6fd9d9dac33ceb6c687faadb7d0ddbf1fbd500d33f7b7ea83331c268b07bfb8a197b04c696af3635b851354420f98ff1f5fd7a32ffe313e1850e3bb827763b687d109381bad6b91955a208d9bb14db841c158f69eb13d93feb732eeb5bfcea69b14420cfbc02e083f6109eab544d4769637cebdce6f6353344d34b7ff7d13c8f908aa3e33da2bb9816f2d1ff71dde86c16c84ad5b2583a31976da4e5ee",
            mda: .SHA3_224),
        testStruct(
            msg: "54657374",
            sig: "903e17b63fed4fade970aabb5e4c96cdeacbb5027fef39ff752975e5c19eda5eaa37ae6bab084f9fce2b3c154616293a8a9976985689b34188bc0196dbfb64236670cb7e98437b6cf68483505d3e819b1fbb9925d5213d40e9d5d44d2efe5fa7abce69b79275130240a26e9fbfa27ea8d1bceb74a102951f5d50b85d0069a1f21324c2a1ec2bf8036bd35b8f62b89f9bceee5b1c8eabe28976648f9774e79a1d7cc3543a9451e2b69204f48339c62c61264098e5b5a8987a8590420046f3dc03ce8983adf8f44d3b05fcc640e528b6e0e26ad3f9d831c75ab142f4751df768e4a857c6b307a1d942bc841369c1671fdbaf19e5d058319cb71b34e593ca84bbde",
            mda: .SHA3_224),
        testStruct(
            msg: "313233343030",
            sig: "80f7552b1372b9adaebd0dbb2de29f77b9a8e32b32f958a70b0d1cbd2057a083f864513099d66bf20753a84329768b27e582a93286f34b1a9635aa6d1727b8195d10bf3680093944f562f5a27ec01d36182cb6e528e4b22719347465f80b3f8887abfa4be1aff2aae97a800a016cf26f4845358d9ca586d8c6927de62c7e7988b72c3594e852c6076d86b77d6c0e2ec5807d4715d87860d79324efb8e456c0321492ea64996e441ed2f2936dd23730486de42ace77d6da51d9e399006fb8810b24dceb058972edb79f8e458b99b9b1d37f3c2631839c1752937ca8405c0bcbea0f712084d7f17590ae45448a0ac0c02344e8f63bdfde99f1ed35f04f99ff0afb",
            mda: .SHA3_224),
        testStruct(
            msg: "61",
            sig: "7b30251a92745162aa07cbd3a1b3ed10389c905c03511a68119113e5550a30075ed0a31234fcfc87a5b0075e8d8a83c41c8ded17c57a1e51ed119c7f721125575feeabd8b87bb2aef38edfcd74bde4ff615fda9924aaf53755a44ff8cc7c30bfa0e7a728dc342e3428b4d5b60f3a0921cee31a0cdeb0625a78a2ca773a08f78f126a454e0358f5d92966e03a918569cd4543f155ffe17816c6aaf4dc80b371eacafee42780989e8c25d9230f6c584a4463864dbba3e45afa3cd616b6d316d5257ed3f0a811578afb818eff09f26dff865f055275fd7e032d353ca06ed31ab0b03125098b073651039d65e644cb7861d549fa74180e1be0843d762edcd439df97",
            mda: .SHA3_224),
        testStruct(
            msg: "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            sig: "8569ff3cb6788ee22fef928d794be3470e7c3baf35abed76f93612421b41ee75d9f5b3ce01b53fb0c66955b4a8195200dae75148342cbc74d26af1029ad8d0a6ae1a863ffd044c974a978ba2456a77e288245d268085c87ee36aabc311711d2fa72826c949eb46481efd20718a0ffcf12daad466cc8ce8d0cec014bfb70ca6d674f2d526166029e2b33f6cddf4f900c3dbf232eb9470560589bec5c2fd1f492ad9f74d9dce32543c59d48c554a09526dcd72b4a5a5bf1fd1c2b83001c1b77a703b5d6e643f951ff0dbad816b89483222e6abf8d3e2b517b64f44549f2610c5730d2460a5ebb36cd64418161c30043653f4a033c3c46225cfc785d211a720f3b4",
            mda: .SHA3_224),
        testStruct(
            msg: "313233343030",
            sig: "2203f83bcddb3e5740f0ede33cfa8ea5cfd943de391418f34aafb1a54fc138db90f676bb5067bfa0ba2bec77211902405474262d049c0fdd47933706692dfc15009c1e02005bcaeb9ae22de62c52632049b4e320cfa1f5448f2d5f2521e48dbf4e008bb71e7bfdbef5b82bc997bcbe041a43cc1af056398b05e356fea16b5406872e50a83cd1d387ab471a70192b7c38e602d31a1a21f20979d7c6fc712b36316cb7aecd4fba57bf2c0f4b77b3eaebc694e390ebec2022917feac3d5514250677358a0cbce253e07140073ab407ea98bbbbd7fd2a73662b9fb3b974dfdb1e173609619877bfdccc157067440c8bd16dceb8d30ef6697dca85d06880d33ad5da5",
            mda: .SHA3_224,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "8cf323a5071e584945b950efaa25ac4e8f189cc5a44914c17c01a8d38c762790d6eddd012380478e72cd3853bac1bd9b8be90d5c438d7855fe5df3df837fe1d0eb19b8fce5525aea208fbabf173ff4658f9b142a28ed00dcfcd51eac5a7e842b18c55e34d64ddda13c93610ed640377114631f4d255b9ea3da0f84d3289f9f940bef25e74e5441d5665990868d86ef98cc76cc84725103a617c815a6fd6388b4f58d23477afb541342f38c9a1e6124d0d13c5a54d1f734cc82eba225752b66d39bbd5ce0a09cbaa1caafa1489097cfd28bb418f7f1fa0c1786b51ed6ec5cd7292e2e7258f59a56b8671e5785d02f1578c9b2f93d62f955b77fcae63bb3d65229",
            mda: .SHA3_224,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "0ea6156ffe6ed89084e2c1e479a75ab946f480ea0e468373899daf25fcdfa7649b3aa7714c0d1107120bb412a275b3ea92387078dd7a6683aed58f539c4ce52426ebf004279427fd9fb405b17ffbb11270fd2eeef56c1f93cd7c1900cd92a3204a5b4acde3f6a999c679b701a7c2ba82e39263a3e2a4c5be781cd2408baed560ebf3cd0c465fea56b1a0834caaabf413ba82f2ad34a80cfdfe18101dcdc3c5f62ec2594dbcfadeae628143408cd107ca08f46811bc2f611ef157d9b38bce72a0cb433a742b7e53b7d13d528d1e7bba271351cd88e71ec6fd111bd34a37ccafc492e91d149ad22de31fa7f3f506d5ce4552554fa1eb95fabf24f366c5b8fedc45",
            mda: .SHA3_224,
            ok: false),
    ]

    func test224() throws {
        let pubKey = try RSAPublicKey(pem: pubPem224_2048, format: .PKCS8)
        for t in tests224_2048 {
            let msg = Utilities.hex2bytes(t.msg)
            let sig = Utilities.hex2bytes(t.sig)
            XCTAssertEqual(t.ok, pubKey.verifyPKCS1(signature: sig, message: msg, mda: t.mda))
        }
    }

    let pubPem256_2048 =
"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9A+oIT0u+ihfaRSMFwLy
RhiI1LTgSN7AOoZbP16BnxDxLyCcGWZSEHxouDfRCxys8C6COvxCXpBMTyT0VQ7u
aComz8I5sTDsuJHh4xWAWbTZDDqgbohXLPGGgL9lUqkATl57EVEvG7/lGFz9x+u8
r6xVrEhGxYPkmpEkPQC99FYeol+rvlvYQ0jjMUMs7sanJRUzvMJQyocbbj78IXAj
hf93e2djbgLJmT1XK8ygj7JpFsyk0XzjfDZVjxCj+5OzJz1lazRSJTvAasEqEUIp
xxvILwlL3V23T6ODEvnKcSlPH5ljYPGAiRy+ccgR3GxVNPenHNH3na9h/CeJx2lY
owIDAQAB
-----END PUBLIC KEY-----
"""

    let tests256_2048: [testStruct] = [
        testStruct(
            msg: "",
            sig: "e993092e99924c3319b6f3cd28e84b34ca312e32785d8ffd57491c2a1d59f07b99af1ca059207e1080bf712a1eb8197790d1d0d4840cbc367c557aafcc954bcf86e531d5f66515b3879b9ea26825df55d4ece20205562b12edfcb66289992a691e437b301a634580099e87751bad5331776c9875924b53967ef01c2772eda65bd8192ee40a37963ca80f6a037a2162a5c577f706d2c61be6fd557429df068922160a549447eb35c868738146e40477d72ad7da71c20220da973e32c08c682624cdd9195e258b3c1983de3c3547f4e8f8ffe8bd5013e9b1a2129baa08202b9fdde7edcbd181282de3d283e2636befcaa328b146407ac4811095d8f0107723bd81",
            mda: .SHA3_256),
        testStruct(
            msg: "0000000000000000000000000000000000000000",
            sig: "74d9fb09765121862f7658f308b7c102c7196b2a00287c1e3fed725654878110b47c1273412669b3d10dd2b4d35472896e6ea4c8ecd4771f234a83b7c978642c12ce91cb4a97bd001882dd32eeb8f17760caa2ff8855cffdf7888011cd6cc46510e920a7e158c722a6e06857f8e1cd964f8c8e5c381c909c459de68f787169217867005f1b14abd698639ed6dcdc045ee9969e5f6a5c1856cb785e81c4c4e33a51858ce57c85546bc1e1282730867682df3a1624593d29b75926c9e3eb1d90a4edc6eb3740719e07ead011c8a7b3c7a38fda692257b1c1827f7c27c65c84c4ff3d7ed3565a12b2ece814f8b0a7885c2f26c5d94234e349c9c577cecd029dbd23",
            mda: .SHA3_256),
        testStruct(
            msg: "54657374",
            sig: "ca7f638c60ee48f976845687d9d7f3ab80899f94b92aa32117c220d21bee3e8ea5723d8c720f878d11d75424217a9ca88ed678afb68d3a202976d6ae7252c85c33cba7aebdf64afd765ef854c5245f123354a26665fbad66d1d9ece4b0dfe6318733c8ef8daaf5fa197b3c22172f10302646a1b6bd789d7d5101ba42b9ff417f3918c78922ea110a6a70bc781661a52c5d4e4390f6bbbd59949b2348c8e30360bd4cddfe5c3e6e995d60c681aefb0a328b955e21e3f8eb86b0693c3fa566529494bdae2557622d808842f8ccf34db2b72f22cda34f887473a41ca8ba35b97436271365335d50f4ada799e31c7670cb50050f77d3d4087b439e34d9cf3168108b",
            mda: .SHA3_256),
        testStruct(
            msg: "313233343030",
            sig: "77938d54f08dc59bcfd4a4a7cd6085e5173284781181adc81e0ff8caf7864c5689447676bede0bbc12d9c35b6ad09fa0bca2ee1ce9425ab063c08002477e4eb6fce9f6cf6c8c01fd3f5a72580ef7a62c202e9689daef8af1c33f8a3861f9acfdf79bf7075f24267ab4b6e257a53cb68f1c84603e63913df8613890525ab205a508854713da596b79466e4bc767b70900547c4f1e8974a7d0ebfe22c749d4e2a95a3052c2883e253ab418bdceef2aae6395b19358466d5c85a72038e359bf9ff285d565494a015f01f24dab9f8e7426d7e687190373972ec67661d28388d6a763beb7458b432625e25ca88a945eaf4098768550eb75457a9c000a92c0517c0b3e",
            mda: .SHA3_256),
        testStruct(
            msg: "61",
            sig: "8be6d30510263812538bbd7a28ead1f038853a5f307e472164d78493f3d7c6dc294f7c4e359d1f9a2b2b411ebed74599dcc6732c1bad982fbdb199a0550203f381d913f27daed5e1a4eafcf8942a9405ffa3deec91d7f022333fc5187f21c2a72f8f33ada98c04687cf3a2f44738e061d140aec8596be4dda9c94da1259c149dc6cb4adfa859acb915ae3a5cd766ae6cbd47589adf9b8f67f4bc16d8fd774403be7c0b0249d356c383aeecb5ec2829061832443e67f2fcc71b906f7a2a021f545e207c5aaf9cdd9ac43ac885f0e962ae99d7b46c1f208bb8793a1288bf0fed511f08c94b65b43932649918c27ca246642dd2da0635b49c440b6873dfbb8599f0",
            mda: .SHA3_256),
        testStruct(
            msg: "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            sig: "c5751584130c9089ba68ec38f60e50788df91abffd27b9ba0b2d18ab82c1f8466ab801322934f2ea6c07b65c851b23cde2fa8420f05e256b8139a123c9e98c49c8025ab0f61ff6d9243b0c78de55a8baa207d1b83f9591b784daf59465775532d8bb85b6f88700ba7be96428bd4c5a24c91b8c05d1d7b4d4163ba69fe868e639d6e5f27bdd676e74a82d7b03d97d6c1ce2ec09f173713f891ae819794332894fbed98b538d9a4ac7adcd6885b05896ab897ca50e604fa880e9273a44247b52d5997bd978c321d7d0f7caeb5e2c3991de013cec31f63cf75ec353c684fed12828012e243f14bebec505388543f2473668ad4f7047adb7fe5c440ccac09be946c3",
            mda: .SHA3_256),
        testStruct(
            msg: "313233343030",
            sig: "51a6c8800373c3d1179c3528fdada1875c765adebaf20a4421d958ba741ffe7278de637ada9d7585891cb4b6d8e3c6512167ae9f0af7610d01c7c638a3c7796f21dc34b2be0192e16f82cf296f724970788703807d00ed105467e902bb5925426da7cf07c0aab07e69146ae9640e5b00e0ff8633d960952246ef2283cb5b8485bbeb58232a48e52b8d4879bfd2c5277d61c0594e50cc5c8f144384f1e1dbb1f922c9c49798b1f450c1cc6c1b12da4306b81fc7d15183ba2c80299762a7d0cf48402bca2bde343649b27bd9304212a3644ca8c99f4a94a3cd783ab710fef961aaa33ac7442500aa77fff72032b158e24b99ca92cb81fe5835f12a9497c0734b3a",
            mda: .SHA3_256,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "a95097e1a9a3cadedea8b321c97f919db55c3b642d5afab2c16e326be7cce4db42866d23fae612115d4da3b5f0c00e2b07c5e5701973d437bc48c3ea7fa2e6e4489385f67f5b3193244d44602ae8484d5ae4a10a6be82a77a429f3a3e5baf7022cfc485b071002c50e80d01098c1d929afd598540d1f555a99193cb411f283ca3bbf788e3c1079229c3195d3e44b0bacca3858ab4ae7296ee159b10612568e910cf19bbc34746dfc989679ec8a917b3ed37f50398ff14f9721c3c705debec1a8c7e2380be785170e0546576fa08c73d65fb0fceab8f6498b5240fcdd52433a5994bf1b76c9b4a87ef50904c4cc7351621efb6041670dde6a3561cfaddd4df59e",
            mda: .SHA3_256,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "3774faf85a48826745e08d70931b6f84c456ddeee629be2ee8465d8111cb3c8cfd158bff75c060bd88e3e1a5e8099918cc1508c8cde4a37ac3753e64ca4fac8e143246890852f05dc970cabe693c6668bd06d5cc2e61f8d06bdf437665f72dbdcbcda5947fb530184fcd88779813dbaf6cf21c7b4f382098a1b33db5733d12808004214f812c9371eecab83ad249d7d54370a4ac14074074fa4a2021fb216dd1069d236684fd6e5ee2d7f108cea0dfc3fa3fcc08feced41b35f8889c9b814121541643e85d8e6e21dfa6fe17b3408a12ffbfaee86b6b91740333d228012e16c080c55aaa786062b42a58af8a5ed91f44b1a8e7ddabe2815641fcbb0b1d094ef7",
            mda: .SHA3_256,
            ok: false),
    ]

    func test256() throws {
        let pubKey = try RSAPublicKey(pem: pubPem256_2048, format: .PKCS8)
        for t in tests256_2048 {
            let msg = Utilities.hex2bytes(t.msg)
            let sig = Utilities.hex2bytes(t.sig)
            XCTAssertEqual(t.ok, pubKey.verifyPKCS1(signature: sig, message: msg, mda: t.mda))
        }
    }

    let pubPem384_2048 =
"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwEsrJ/w6EHQ7Y6wrTNo5
Eao50b2OO5eqnpq5qjHWSHneKc2JGsLodQBnM6ybkqLFMSOWZmOLzI3ciieMHjfG
iEaqTvf2DqRL8upPsTT2odlBj8sNo8SOoUViL1uur3v1iFRwLS0x4oKIbD3nFoeY
V9238mI69vIOGwPHvGE5wlM335qZyzt4++12Hp+bWDnhG59DU2UuZcWiMrYDzmF6
ewL4CAFes/y7KI2vPBTI07T6zYbj02iPiAHmCrm2cygLU18XRNfxgBwfGYiAbyEp
x9r35uU/uBCKeIDEILYfF6tXJo3UWXkuXZncaTHCd1Ea3IyMW/BL78HS/OEQJGJD
MQIDAQAB
-----END PUBLIC KEY-----
"""

    let tests384_2048: [testStruct] = [
        testStruct(
            msg: "",
            sig: "6c0968d7d4cfcb3443debd51062298502f27972b1224c6ca6a58ffd5679245d252753165ec609f5740098cd243ee92193d551b694eb4714ce432dd7cb4b6399bf5875c805ec5a2189bfecf2279d1e242c77c0080f9e4be8636044f912279cf66dafcfba417f0a172235f7179bfccf85d241cb3e8b36af15b17ec030c2e3255d5d36cb13d8cfb6ffc7c2ad40e44a4e7345c4a1a0fac8614559bcd06c7409770284e362ed71735e1bb62ba8057cab9351adb844c91227a148aae37e8fc8e7656dea1e23a7bdf2e3254a4cd7974d8f721360019e084f36fecb8d100c74e9884270336adce80b44ebd48a7e48758db7b2bc3a8a87ec342d56ebf4c0ad4585d888fff",
            mda: .SHA3_384),
        testStruct(
            msg: "0000000000000000000000000000000000000000",
            sig: "01cdc5c2a9f58b6afcdc38db418a54aa3b64d98564c0b0d9e127f354a642ab67733227d3e6cead314aef36261e70bb362f517c548a1180469e79f21a08a06795694018b75208376dc0273a69b0cdbdea5906e98d71fd947d7fdcb5f26a84980924799971ce29195b21e88a8418637e0cd9cbce4d0728eb75865c8f3efbe5d8647e6a89d9bc0bc65039da450b210b8a21302a4f75a9c2b99172934861e95a367348b6d4b9a399d2adb3d2094eed3fb7c2875c4ab08ef794547b644158d58bedce3b6012fcb9fa824320adaf7891eb4f21e64f88f91a069c7d1c9dfe1ae466acfabcb53ef4db0982ffc8ebb1192e218387c0f9c08fb98a9ea47cc30741b3680ad2",
            mda: .SHA3_384),
        testStruct(
            msg: "54657374",
            sig: "27897814e35a9e331fdd2d144e6427bd59825853bb6073cf3c7ddd75152ed00fa04c249bc64abd605223f6c12eeb7b1bc128ae040317ed7837db8ea0f1041df4364f779c4d2dda5e4f8106ad588598438bfddb18472953c7ef73089c8a330c1a683a4b809aa57218b6909ae21646ff5af6b4403deaa3e1fd1ceb117b701e596a021487aea5c426c13820c257a58a89d789f3f9fefc41b3c484d62235409870d42582f725be14b0b2ef758100ca8469abea3d505c33f04ad90b4788f87fdf0345e3b77f9bc4653617cb03b12e88776f21c2f5d9c5bc510a955576d27301ed338ed606ce611936943eca621e3755ed27bfc2b58253b726a473f1eebdfbc098e8eb",
            mda: .SHA3_384),
        testStruct(
            msg: "313233343030",
            sig: "37a18f9f6d9ba024a9a2525dbc734cb5933ca580830018d472c6a07f29f89e5fed284555ba1e17cca73c55def005a5705a7f4973f770e33256f355bb2e4f8d62b81c59b7ba8f878c7cdb603b6ab4d0b794a56fec6dd460b05d50a18fe4b7d4ba688cf92eaee669a463709dd5d3664f51c59bd2f3cb2c59ab25dcb997c803998aaf559d1e4ad04b83a77224f63ce7c56b8404bbae7d66d04ca8437c3b57603a5ecb1d994e0f4f66b92e9fb17f8150a33d2c79232da83b500ab727646e427d026ce8d544269c2676ed0c690f45218a05ecbdb029ab23ee0f27313c54d361f88d91fe64ee65c19f0476bb27c079160c8a7b90bd15ebf82ef244e1747cc0465323aa",
            mda: .SHA3_384),
        testStruct(
            msg: "61",
            sig: "391a5402eed1ddaf18c8c1ecf2ac280e2d28dc5dbaf4fd45d6da06bd6d58c8300984a282e96ebf49d31ab0e53dcbc3acbe41ac163c0555f7391e9bc47c99789df15bef47f75c985301fd455872d6afa1a557414a85ff8141c384e1f04db25cc1ca913462193bbd620a96f7d752b7e49d36dbf2ccc8e7c21d4e9b4737fd315bbcb875ba203fcc7ee1d3302645912d68c7196f19ee69ccf25c7dfc9a70886fff8b444edf70d72434b1a78dfd124304828697e18f84f873f20fa7afd5903eb3403a002baad93618d24d51319e166b597c2b5920ab2155a0e2d03815a75bfcd55f3eb5fd48662c74c0de8de801d0088280e84b9a4ff31f29f883ec2a9919863a7570",
            mda: .SHA3_384),
        testStruct(
            msg: "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            sig: "9c72b9df62fefb57073ccd964adeee1a5d93e5e8584a27686c2860849b55f65f468a221aa82b1e9cde25b09c3803b34a53066d4e1741a7d98dea195ef22739375877750ec446e534053019c56308ddaefc21cf07f5a5fbf0e397d7d0ac5aa42ae45b2426836c5e1c897f59d8d701c274be42edcbaaa9662ee35b298d3b76b30db151e7fa771f13d654e5a62b65778581396d23c182dc824edf5530ddf943218fb6db69a416b5db1f61e9ecbc9180c87914cc508643903b30ed49d25968720818391e94b4716d8e21e023ebbd75c35ef015ec094a5290d3defac1480aad42379a23664e698838c95e559191380baac72b0ed28e309e93e24de73cd80b58f0ac05",
            mda: .SHA3_384),
        testStruct(
            msg: "313233343030",
            sig: "b46a26147bd2d1fb421e2a7adc39d869c0d28fa431b5b1d68f96158df4170dc5fe665a2c18a0c7671c1ca29bccfc98fb49cd9788d249b8fad7429dbe6da6fa64aeefb21d88a01e035a6454a783dbeee18f21a7295b388922ab99c0aae14ff71b5b426f7aaab9aa583e6141a16c34e626ac8e00b3db9e74ab11ac8a5be213347fcb6c728fc61c58c62703d66cb52efff4fc15a22cccad88829de41de355c27da1e5009921dd59703e94e55d2edffe398c5f8ff82cd6dc979b29ce6afc0e40ce16a90a0b6db71226ab8aeddc855a43d12970bbf3330a69f7825e2722104941b8904639e254e30232c17dc4c3684b3e4b0606209c3c199bc360add2a945041a007a",
            mda: .SHA3_384,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "90e8d3f64206aaec1d1184748c58f4ae5129843c7778647f6f5e98a2031806115123159ed2a253ac777610f17af75ca3d874a534fb84dccd595de98a54bd8069b05ed2240e183e5fa98f08aa2345d4da516b4f662d955e88aa200bf30abaf110410fbe616556a81eceb0590863b07b2994b8e076ce8260dd7cdb07ea7ce20670bcaf7f6eca3d2902f10e2dffa23220b8e1e3f99717677d5e561bbb06a21026dc9d6c73c930dc2729c8c90a29f0dfedd264193d845e44b21b1bc9b74dbb82bdaa4887c39ddaa83636f89ac848546ef4ee7cabb5009d19da6866f904229290abf3cef456594aff8402ab2a0fc465665f6ae6986baf79a621f0b35cdbe99a1e7577",
            mda: .SHA3_384,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "5408a4d48a6aca7ebdc61ce7dc20e9add7eb0f388b782cc97996a5114d7e014b5be7a5e72b1e79e32c369b29ea3df52f5af3a43d6fc87e647124c5d0acdb0d75fd00f3f1305aee7bab39e4fda0070b8cc7c717c1b81ccef1ba71506abc7d44ed0c18e1371edea6410d079526397e51f2310d51d4fe01f758c579e06b8af2331c71c7b4352013f4095d9b27d00321673e1478bbe16fd24f1d89265be9907d8c9e8825ce8ea18d9e982452aec7672e9e8e3fc4d56bcd688b814a0a83fc6c237e7f3fd83889b40494747d2f0a4f39d449d4288e202d1712fcbd2b7fedb2ef0291fe4f740b7bffc308be6a00de2e022a9d8d33b3169cdd74ed3a3fb340aef1f34f12",
            mda: .SHA3_384,
            ok: false),
    ]

    func test384() throws {
        let pubKey = try RSAPublicKey(pem: pubPem384_2048, format: .PKCS8)
        for t in tests384_2048 {
            let msg = Utilities.hex2bytes(t.msg)
            let sig = Utilities.hex2bytes(t.sig)
            XCTAssertEqual(t.ok, pubKey.verifyPKCS1(signature: sig, message: msg, mda: t.mda))
        }
    }

    let pubPem512_2048 =
"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqtncGsQgsIBxuiCzjim
dmYgxkQTFn3DlfvLQ9be/OayvGLIVQO56zBXMOIJsEr9irLBgrtjZbRjlFQAk+tF
XdPt7jA3UEaq4D2rLjK86TnwEHr2p2bE5I1m140EgeIsI1V1uOdoRyZyQbF/TN/e
digBbNqKxg5VURhjv7VbCeuGpiR8Y9xJbhWmqVcMV1O2wiR1LzR/IlIKap9MGiGI
GYX3vuo8pbCfgHutRRs/UeYKyxtqupT5DGETL+MKOrrZRPPuGqcOxc37QZ8byH8e
rYxJ0iYbmUGE3948h3UkMntv5Z118iP8j/F340OmSQkV9Yr5ksXO0z9vQcL0UrqW
ZwIDAQAB
-----END PUBLIC KEY-----
"""

    let tests512_2048: [testStruct] = [
        testStruct(
            msg: "",
            sig: "65d95299c00d0d23257a660b0ed827a4af4b442e041cd572e08ad5b61c35953d1f35eabb2b37fda110de050030e107a284e69e2a790862bb879358cd94e9e8d736368d4d4d48281774b6d40002b9dc528fc2916bf8e5048fa47dbc95dd69081aa93fe7c009d2e7013d35eb586c3ad9f2080c471cbb9ad6b421cdfea048d0941a3a284c76d11d98a202a51fd9373f70e4e255a699c36042d49729a3c0fd4143ee85c979bc5f58aafabb1ef3be4f0aa1e8f031c681e302b48ee92acef6605281067c78bebf3f311ecb8286b411ae4b3316d74724b9d9b3c1c3ffbb0e9e6fbbc4ee87f78a66033c0e98bf8f72d9b9338e3265fde31250be00a70021d14487c6061d",
            mda: .SHA3_512),
        testStruct(
            msg: "0000000000000000000000000000000000000000",
            sig: "946edf1fc55945e0c1d5d6653245ef2d04dff3f1b29fb559f32882224043b8b4c4a04389843189256cec4d5dabb67de981a5d85b6b5ee41d24e371cbbbd7d2359b1efefc3fbe77b9b4b901335c226e39bb0345068b984725d3d2e5c3c4a5f8aeefea26ba5669b7b77e027f77b29fe01c4a308625f849321f5456eb0fdcb83a520343de57614ebb8ea88215117e5a0f1f0f8d7827cefeac349458da21e9c686eed931dee5320ed3d30ca833628967ee0fbe7a2a785897fefb4884b4b77d6cdcb8203663b711384b99b8d04e022be89b84865af67a0a53f54f19fa40458fcf0114faff2c0b17045ca55de3b48631d51dca078c10f5e508d97de9a2961492c40992",
            mda: .SHA3_512),
        testStruct(
            msg: "54657374",
            sig: "153bb04802abfafc890293447e4fe23d5f7a25bbbb96fc81b24e1c87043ffc335f7c96808c876f4724867e3b042764829f0eb6b2f1bd4c637450d45a099291aa4e9a1a7944b9221389fb0f6ae5732b73be700c13a0117b1a3c18c62a7d25f4eb8e7a8d302761e0013647b2b709dd7b090a6ab328d467e318685a845d183ce01a9b588f74e566be10d50d9cbfb110dfac7655c5814c415fc7b7b169a8a3738be2f1e04cbcb5a1e49560217e72a42096e43d1b2eeb60a4c3c7ac98330b87e1f8b0c88795da8fd2861229746c21e2baca38e4af249c086b00b6c2f6540887b54663da6b267d1917509296ffc793e89c935916ce802c9bb082f14fd31880fa91e69a",
            mda: .SHA3_512),
        testStruct(
            msg: "313233343030",
            sig: "a91fd64c2e820a21f0d4bdc5c7350737eba745217a98a5dc89ac9014e22b29d30e99752761c08137451db8c401327e69a14785fbae217ab57fa6742ddb97b20c5db2ecea5fbc9d6b7383cddda48d6641cefea5e0c5ef0af9d79265b8eca8de8fa3a98b5e4fef0e2c4b6af36a1fde2b16ff2c2518cf95d31142a6e2246c79f27e5786aaefb99a548ce6da1f635271349c93beb7c327ebd3cbe8ea7d9fe38fd87184a79666a50978a9e31697807aec6f92f2fb546bf1bb55403162fd11e14ff3ca5c0cfef400692dd6d7557f63862a6683014ec18d2a07ac52635b54398865c6b3246c769950f59478f282dd87c1411a62070746c11827f14c783fb647a5d468cd",
            mda: .SHA3_512),
        testStruct(
            msg: "61",
            sig: "34740be5264660983be1dbed8c2992ab01ed57352985fc5ac947e147bdae9f9d2045f76d5bae65e5b577e7595d0bd05dd1b51d6edb42aa219dbf745980ecd5710c6bb1f4f1bae9d6ee4dbf8ba8a370c5e17211edf40e7be4453b4cad700a84b58b69d5504369945dcd1307cc485c81192e7bec68b70740d19ce2c88931b712bbbbcdb54e27f6ef34256252a6049b4f8fb82d6e636a856cc461209f6b830d0f4606f41639cc3b174922ff883ba4f0209513c0c2b1445fd8d0943aa36d4e6c6799e44e8cc1b6941d0b9ea4553e9961513e115e68a1873dc421e29339a8826886944f811256024f46e634aeec5fe51eed65de8bca46bb030aebe0b9d9d2e9acb6b7",
            mda: .SHA3_512),
        testStruct(
            msg: "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            sig: "6fcd55e9349587b9adbdb009cc4d4d9df4fda53bba2301910edc24ee1a97339af1a139a3a7c1a862238ee8ec6672a9624d821994b0ed5abf2ef6abf2d243c3ba131f90758fe927710a5c1c297ef9e000af912ecd55495af07fb625e6bc0c87a8622da4dd8142fb57b67f7283328a90205fd7a33bea01b63ef682f63a6e92b57f6f32cc60a0f2ef1d619ed2713c742854f0aa252a698a28a073bf048462574edd2c8e9dd638fa2961ecfa2ff1d8b0db202f4837db2e1d345d6cf577760ee8cd874d117ed433945199b5d27da45449980603655d104946869cbbb47001a9e38f812508b32e07acbc58c48a7fb5a76140625270eb614e0cf8d6af13fed6b2b8b5b6",
            mda: .SHA3_512),
        testStruct(
            msg: "313233343030",
            sig: "6c8eafc8d00b907fe7083eb2eb8b4d56c4cb201c5c9a1fb4f9bc6131c894997137e40e9de1186ffeb1cbe4ff7ba0329987009b55e439b17aa88016e6cd4588a27a85095dd70f5408fc065ad09b28c076d79a2227bec963528312cfde86d1c5591605f3ba5dbdb7276b25e1a70942e60bf090dc19ef443028108c9438fde2c0b73fb3ab5339d158ad8a0708197f3315438fb300731269b42c9cfe574a905c314a6c021245677174ff1a9500062f38341098c0f100cafbfb698134404cdb2395e658dc6bf136bdf44e9d74b7aa5e6394fd5a926e86247297031cf958936682a7078e5659e063122570132de09d9d9270fab96c1a99b11182bfca66255111a70da0",
            mda: .SHA3_512,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "34956ba7f15d15ef2113d94cf92aa18f4e320d66706fa74af34f105d317a28553b47683168a59ed73fc9b14012312369132eee9b96c63975f20584cfff54898a021aa3c426ede4a4fbaa5223b77d5ac35f52048b4893959dd8eef19321c3991e2ebd8a50a27ed467e92975a32a4b192bc807558306240054d8b0a03d8c826f126edf593d9ab810c16d336f07f898628edd6ba4e48926a46e8fa77f3bc908b8d34c804f8773b3ae239224a2bf9e351ad0c5e48472da6a5d29d6012ef82c973a21d6e9e6f32680f909d7cabc737ef8ea9d6c987965e1c712c0b74ddc970a8dddde5a1b6a1bea9b9c8315aceb9a74e22d0a04f188140745b55681e8a5e0650a1a7d",
            mda: .SHA3_512,
            ok: false),
        testStruct(
            msg: "313233343030",
            sig: "7c1e9148d575f3adf89c8eb83b709ce1e341492e8fa59bd6fd31665e7f9c0c5497849822d3eb6e7032570f3efa9285fc93017a6468e30a42f2f80ec448058f9f318ea5b0057ab82ac56d0a3be1c175527224b5aff7b258be1dfe0bf1c09482e826ec335bcab76c6e624911fd29c9407b0e9713c134b32b68d0e26dc56af05d303b3429c6f31b99c5b997bb610460319fb23d3c1c1eea57a45fedd9c855c0d7ae244f327a443640b8a6fb3e18c772f47e54fd8b5cdc10ba5fcf32be2e2ea1ad7c0054a129eda401379211ec2abca1afaa29a652c5fa91448b3f711a6cff43b01efb1fdb643a0a17c02c1f0716796bc97dac00ca2d242ed65647b1ebbce6ccf03e",
            mda: .SHA3_512,
            ok: false),
    ]

    func test512() throws {
        let pubKey = try RSAPublicKey(pem: pubPem512_2048, format: .PKCS8)
        for t in tests512_2048 {
            let msg = Utilities.hex2bytes(t.msg)
            let sig = Utilities.hex2bytes(t.sig)
            XCTAssertEqual(t.ok, pubKey.verifyPKCS1(signature: sig, message: msg, mda: t.mda))
        }
    }

}