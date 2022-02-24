//
//  EncryptPKCS1Test.swift
//  SwiftRSATests
//
//  Created by Leif Ibsen on 10/02/2022.
//

import XCTest

// Test vectors from Wycheproof - files
//    rsa_pkcs1_2048_test.json
//    rsa_pkcs1_3072_test.json
//    rsa_pkcs1_4096_test.json
class EncryptPKCS1Test: XCTestCase {

    struct testStruct {
        let msg: String
        let cipher2048: String
        let cipher3072: String
        let cipher4096: String

        init(msg: String, cipher2048: String, cipher3072: String, cipher4096: String) {
            self.msg = msg
            self.cipher2048 = cipher2048
            self.cipher3072 = cipher3072
            self.cipher4096 = cipher4096
        }
    }

    let privPem2048 =
"""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAs1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi/fGHG4CLw98+Yo
0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv+6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM
/ZfSCKvrjXybzgu+sBmobdtYm+sppbdL+GEHXGd8gdQw8DDCZSR6+dPJFAzLZTCd
B+Ctwe/RXPF+ewVdfaOGjkZIzDoYDw7n+OHnsYCYozkbTOcWHpjVevipR+IBpGPi
1rvKgFnlcG6d/tj0hWRl/6cS7RqhjoiNEtxqoJzpXs/Kg8xbCxXbCchkf11STA8u
diCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQIDAQABAoIBABpQLQ7qbHtp4h1Y
ORAfcFRW7Q74UvtH/iEHH1TF8zyM6wZsYtcn4y0mxYE3Mp+J0xlTJbeVJkwZXYVH
L3UH29CWHSlR+TWiazTwrCTRVJDhEoqbcTiRW8fb+o/jljVxMcVDrpyYUHNo2c6w
jBxhmKPtp66hhaDpds1Cwi0A8APZ8Z2W6kya/L/hRBzMgCz7Bon1nYBMak5PQEwV
F0dF7Wy4vIjvCzO6DSqA415DvJDzUAUucgFudbANNXo4HJwNRnBpymYIh8mHdmNJ
/MQ0YLSqUWvOB57dh7oWQwe3UsJ37ZUorTugvxh3NJ7Tt5ZqbCQBEECb9ND63gxo
/a3YR/0CgYEA7BJc834xCi/0YmO5suBinWOQAF7IiRPU+3G9TdhWEkSYquupg9e6
K9lC5k0iP+t6I69NYF7+6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ/+F
dkYlwuGSNttMQBzjCiVy0+y0+Wm3rRnFIsAtd0RlZ24aN3bFTWJINIsCgYEAwnQq
vNmJe9SwtnH5c/yCqPhKv1cF/4jdQZSGI6/p3KYNxlQzkHZ/6uvrU5V27ov6YbX8
vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZz3s4Xd
hiJBShgy+fKURvBQwtWmQHZJ3EGrcOI7PcwiyYcCgYEAlql5jSUCY0ALtidzQogW
J+B87N+RGHsBuJ/0cxQYinwg+ySAAVbSyF1WZujfbO/5+YBN362A/1dn3lbswCnH
K/bHF9+fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT+uwQ0misgR8SQE4W25dDG
kdEYsz+BgCsyrCcu8J5C+tUCgYAFVPQbC4f2ikVyKzvgz0qx4WUDTBqRACq48p6e
+eLatv7nskVbr7QgN+nS9+Uz80ihR0Ev1yCAvnwmM/XYAskcOea87OPmdeWZlQM8
VXNwINrZ6LMNBLgorfuTBK1UoRo1pPUHCYdqxbEYI2unak18mikd2WB7Fp3h0YI4
VpGZnwKBgBxkAYnZv+jGI4MyEKdsQgxvROXXYOJZkWzsKuKxVkVpYP2V4nR2YMOJ
ViJQ8FUEnPq35cMDlUk4SnoqrrHIJNOvcJSCqM+bWHAioAsfByLbUPM8sm3CDdIk
XVJl32HuKYPJOMIWfc7hIfxLRHnCN+coz2M6tgqMDs0E/OfjuqVZ
-----END RSA PRIVATE KEY-----
"""

    let privPem3072 =
"""
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""

    let privPem4096 =
"""
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""

    let tests: [testStruct] = [
        testStruct(
            msg: "",
            cipher2048: "5999ccb0cfdd584a3fd9daf247b9cd7314323f8bba4864258f98c6bafc068fe672641bab25ef5b1a7a2b88f67f12af3ca4fe3c493b2062bbb11ad3b1ba0640025c814326ff50ed52b176bd7f606ea9e209bcdcc67c0a0c4b8ed30b9959c57e90fd1efdf99895e2608095f92caff9070dec900fb96d5ce5efd2b2e66b80cff27d482d242b307cb813e7dc818fce31b67ac9a94501b5bc4621b547ba9d81808dd297d600dfc1a7deeb061570cde8894e398453328740adfd77cf76075a109d41ad296651ac817382424a4907d5a342d06cf19c09d5b37a147dd69045bf7d378e19dbbbbfb25282e3d9a4dc9793c8c32ab5a45c0b43dba4daca367b6eb5f4432a62",
            cipher3072:
                "142b27c795e6d7451db575c90a38488757a5c07760ce10e23a1eeeaa20a08ef14cc07e3ee757c45e309075f7261ee35af580a72c06dc6b0446233687592e838b1220816fc578bf0ccae6977aeddb03fb2c0b5112334acae93f64026afa503d8707faa9989c2176c59a1ec2ff6b6308593c85c11d94a9da2fad66c860fc248f066574fee8b0d82fdc684d8eabbeeffc55c3897099415d99c5d1598cc3ff335bf494c8fd36f234a20566c0d35e3bac56082fc6a81b8cba2c99c47d1d372481ec23f35b62a6469cc42f4d349eea52f7f08a63898da4207e3104efcf81de2ab1e33cd243769bec34df4a4e7cac1c4be4073694bd56170dde8c4e12f85d2f02df12e9936d2990d4a6c490ae0cf6c3bad313f3a477db67332319eeb5932e9d1e1321dff28a866e939fe50626342e141854081981f388489a962f38220ff14a686fa111a5b236eaa4eaf6d3fbd54f93fe744e2767a815adb0c43e947360a149fbf75469957dc3ab8dac091f6339402620424b9cff8324e2a35a5a2b765897ed6e8b2542",
            cipher4096:
                "591be9c4c087764d1c3f38b2948c896bdca19616e70ce1ea20c3c1361d51635345bb8db8f559be2a08dfa6c8e0a717e9c6974762b73927213682e730cd4697d377f8c36ceab1b52fa4e67f7f230a1e3a551a51b6e355f3d40042d3508a0898b061bda6b6cfd1a13753f3379a1ba33f9e303317cdf768ddb009d84a357231d04aa159d88756f8037bf1da996720dc0360998f2055c1fa37473047bcad28b5c4ff5540769d6f23815cc0078821c1976249926310f0fa4013e1dd0bc7294f4e50eaaa2f5ae3cf936dea032b42e5889d0f7fb8f139ecede958ff2756be876fea0b426c902682523fda747ef8aee0b72e0a76659a689b989685de912a10cd2c7e095b147294e8cdfc9e272a7dcda458c61a6f94cbd1d54d9cec61f95d7b4698761a3930715b53715ec6183cec159f4b1e532073b7cbb9224e5c0d5f8e36041d5be8f8de2203c66cdef24a278027e5a2212bb5ada33520b304f186b5973b00c5d2ad7d73e404ca1e930828f08c85b62001f589a73ef0d1e8c2367ab6f1a3bc29d9645597cf7c0a85bbf5bcee4c12fc89af545922132759f83fddb369b55fe68f2c93a7d2459b04f52bfc2fc9ec237c14f651b41e9fe813205c345d1c36a838785a2465619fa0d4370088cf2b4083c972b17e4e0e207e142a765529b325ac91e16eaabed7d010e1735525d166cd310caab5b27e56bff36c478868233a38228e0177cec9"),
        testStruct(
            msg: "0000000000000000000000000000000000000000",
            cipher2048: "a9acec7e58761d9191249ff7ea5db499cadccc51d29f8e7fd0aa2cb9962095626f1cadae29666f04ce2afd4b650be59d071d06446d59107eb508cc60545727b0567dfb4f2f94ca60b939c60be111172f367dfd235516e4a60061648c67f5536650821ac2a60744be3cf6befa8f66e76a3e7c5fbc6dfa4dda55ecbdbffdc98d610de5667a4f485f6168b52bbe470e6014253874ce7b78e509937e0bc5f02857e1ad3cf55139bbe6dc7ac4b1ed5097bf781b7671ca9bb58187aa6c71c58ac0561c5aacf96c35deb24e395b6823de7fc96b8031b5906a34c4dc57e4f1226157b9abd849e1367dda014fbf9ed4ca515a7a04cf87787945007e4f63c0366a5bbc3489",
            cipher3072:
                "b5d5116431fc78c12ee663635c9e9c32ceb91a18a9af36ea63e7e6b647e17a981741279957fe4f0bf08288082fd4c1b6b09a805ebfd229396eab3689b5bb2b686ea39637ec69c1b8142c7033c271c9cae9abfc14f8107a8a2d57984ff2a45c70b276167ac8c92a070c718bca9a1a274258fc385a62faa02e8f15167f9e825c6ad7e2358566f79f6641c6e959e3b898ac780e369f43739321906cae687a9d229f9c86fdb01cbf061dd3c53f8d0c950d4226e7c58a66b310e197e757db3516db2388fbee4e4cf16d12bb2786607617e6f6c4b86b26d36efac63fad1dc561b91b66122d9600124e03b18ca58da78f30ab0c31c5c7f4bc059ce65dba182afdaa788cbbdc3bf8d48b7972c5400f14d3d460d329e0ac60ccf96b3c1d5e4ea9f763565322a110de5569fb74b6cd44de2a5777e23c681f3f769afa961c42782dd2e56e22b4af1c777b87a15df1f6cb48b6a39f7396068fe40168c4dcbd3cce69daaed21554a3b15a2ee62974b112733ecd4f78ac4a05c63eb759842f4503a950bc7654df",
            cipher4096:
                "ae1edfea692eca58775d3c35999e5738886a47884814994b29dcc97b99e79d9f35ac1de680ca6ac6638fe73771ade65e74d13f8de01ee5cdf5c4c4ed2b86261218ec529437606353a80fe45be9fc7f9f27850a70653ad31f490c1075429ad5263c46992a1265871a5ecfc7390c86d72ead118028a3fb3b9fc81ad055c137e34c6d56769cc8cc6e9edaa31958d0b2ac87751870f8c955ed2a0999d5638c8a42864174a0c8045a6fa810b6e0204f15800dfea5688d98156b1589d4c51032c7761bb02fb90fc15643db17f398b30f79906c739dc10751011032bc75828322de3d1e98de6f1bf644619e91cdd875f18b08c5876a485d8d46e5cde5435e26eadcac8dc48ead9f9fb747220fcdb09d2dfb1d1197b591b1aa3003c61dd880fc4e0b7da59146e04eb0d12715f6f44704bf0a9a0fd77bc7b74d3b61157ff5b0221c782fc886b9cfdefcaa2cd737178c683c84055beeccdd1d402d538e0b72485f3be93d8041a145ab0d42855706d61056a1d49a656cd67486682349ed0a6f8ff52ff05ef800a969b978f93d441f896302029ce5e8e800f3b5c2bb9c92c93cda18145fcaeb8f8942787074b02b434b4e52b6ddd918c4ad0ea22575fda6b108b6e0b8c7f681767c553f5b6b2ab56bc657f7017d1deff8f1f55906767bd039038373416eb1198e0195112df8c87c52840e32e4d616963b2e9cc7524c21487d7e81696125ca63"),
        testStruct(
            msg: "54657374",
            cipher2048: "4501b4d669e01b9ef2dc800aa1b06d49196f5a09fe8fbcd037323c60eaf027bfb98432be4e4a26c567ffec718bcbea977dd26812fa071c33808b4d5ebb742d9879806094b6fbeea63d25ea3141733b60e31c6912106e1b758a7fe0014f075193faa8b4622bfd5d3013f0a32190a95de61a3604711bc62945f95a6522bd4dfed0a994ef185b28c281f7b5e4c8ed41176d12d9fc1b837e6a0111d0132d08a6d6f0580de0c9eed8ed105531799482d1e466c68c23b0c222af7fc12ac279bc4ff57e7b4586d209371b38c4c1035edd418dc5f960441cb21ea2bedbfea86de0d7861e81021b650a1de51002c315f1e7c12debe4dcebf790caaa54a2f26b149cf9e77d",
            cipher3072:
                "63b63f6eb3fd2322a6c85ed16318932e83f32535b3ec2527fb41dcc865bc44690554467655034ad33aa0fa993788e80654ab0e0174f8dd238ad68c3bc194f390dd38d26408778774848c49a6a606e7fb1b3bfbf5f19db4d4d1ba2db43fefb9a9bac311f2e1fc1ab4f5ddc00a009b9dc435448f250a648b206fe764505805c9bed1729d5bfeaa4fddafc115d281703fab0e79726d5546fa698a45ca6e5e561b8c2964b2da01914f808a498ab77672eda3432ed9974f0a06d320ff87a4222899f893a6cb6abf13d7e56cce2ee7eae67fc26f2274b63ce8301c721d7195158b6c966b8d36e3cff0aec6f218b0fa6d8490493471ee0f08b840b6cdcbb73a164246864de0f35565bbebe51585819e42a425090479537ed67f98236415e6ad3ca81116beb91db802dfb3f9da733f86cb6fa90904c8a382afcbf6162f0d89ee04973f2d26659325f7f00a4ae9e800de6aa27b6c94b9d57791658eb0714b7cba5466ecfe44bd5803647c3825b58c37187311a8b11399f53a877c265da82493a90869e376",
            cipher4096:
                "04327a40b02bf671557124f963a57b3860e92cff62c439c0425b48b4346fc60c0ebf7a7584f94d34450d20cbd877c8d5dca12f517b486c2cccb8e1f467276ac03aadc94a97fcd224994d81672eb577cf0bbd6aa948d3dc4d7f06456f6650e5620435c078787db0f36124b292349ebe011ce54b3e932fac6525a37c793846a4f08ac3694d649f4a04e24e1f5e50f11a0492a68a509cf30e565ceb9931565b4aa5c3514b2ba87c4c0937ebcd6bb2b8248abb0970d30480059daea4c6ae556f6e91b25ffa5a4f723a9bf98a0bff668a1f0c799d3b0c85b19190dbfb5d894f84fa5d72d261dd2c09013dc0981cd0c46d7a08710801590aac8ff17b237387427ab3c6d6f2a59434b37f123bc7fc0a83d5ca5793540cba582e41b262859d36eabd0aa8203ca05d4c16aaf2a7b2bc7f251497d4c8f8654deae3cfffc5d3599ab4779585bf1673196782075a91ee7c3296a2edc6ee6c30344dd0c0a82274ae17982eeb23eca5c39c7d11a2dd171c70108b0a33164fc175425586f714deb5552e90e561f7882211d3f01c07867256d0cca511e61b0cb51189d8e5124e8cacdab6042bd421447ffa7fe6cad8e7f17dd3e599bae061f85bb5181726d1c0c5bbf2c2a5c1e60f486a81782e58d90ccd5a769f98361765441de142bb0a7f7bd406a537d5be0c2773e847b1df1d49ac1daa963feec84954b72a695b74281159647a62a3c19acdda"),
        testStruct(
            msg: "61",
            cipher2048: "8122b33665648346f6cf728f285667cff7f3c20907e76438e64db81a6a5e74c34c5694fb5b4c826067bae94c5176e152eb16884d9c2b63d2ff41d06140c9c39469a4ae05cda86c81ccb208894266f6b24a0f79132f71521e10683faa05c8e68b77dd6c0c04cbfef55a9d1b68291c286e08907c3df029c52e15539027f534c7df8da5637db99355b24576b873c119ff1d74b3c913b70c48f366887ccbe6d206c11657401f41baad9290fe6ae01855a99891700d71775fb36237bd3597ad240fff4c03d1fe599cdec65baef11fbc4889575a55f255b51ec8298595dbcc89659382d35c2b85a941c33746a7937f3d18e27079fc3d2252904aa533fbfd2ebed2e059",
            cipher3072:
                "740486caac4d0038274e7627da5325320682e610bd678923158c7e23ce3d430e6bb0fc1063fcd84cbcb2415ac32128a0e506b2f95899dfc67c2955514d8e0b0e4d84077b869b5f4d13eaf96242a0925692ff69c752190082b813bb9dda83907e1d6c4733af31e00847e856c8d68445fd2021d982a0ed9165db69933f50acae667a5121672294ce4c534479590a9f4425a8fc7c0cdb8abfdbb290c71b4379cf7e7cd959f4557b2aa61e185e95699345aa4010d67efe3891094d5c0ad2310f1884111f4aa0d33cc1a4fa494c5a744c10c307069377c848e7042ec1581f0dce3fb7febd7d347c5abbce2ed3d2ec085644fb661d15ad8aa041a375ccc77c9e01dd47e300324738db555201506ff60fbf6c12a82f6acdf7396fe38e4692d1fbc9d86887709f81697676b0f45d57379dab3409b173827a6619572dd8e168b991d6f9f6b996453544032e097c28c320ee2072d5aa9582cdba70f40ee2aa58b0933896e6c27b0933268cc577ff5f6e9e6a7591b73dea4c6ee24fcc365bb7688eb786fd3d",
            cipher4096:
                "2d452fce3031f644f4a22e0d7b2df7296edb3aacefab84e7c57107021c61acbef498a914b9a70d3e33f97f66767eed7a14c16da88ec156e436245b5d9d7bd1023c997155e2e64d6801b535c3c861b19598807387c0ee366d024950b996cb206155493f0f320cbdf58f59c5911e10db3f8034b89a81878dee5a73dfde620ed224181364e7c7ea5812c874b252ededbe4c8644fdd3d312c7bb4785fff4b23a3ab00a2e5fdb3192404d8f1af8668d89e7b4aaf70634b98d98b2c244c336e57b3cf8411294f1a614f55b06a78e56eea98c6f59b2813643515a919f7be4ed59dabf69d68f43376964f0243ec6dd19a0a3609f8ce3e722ea3375a6b5f7ab24eafeabd58f81a2b3d2bd3aea2e6cfe396542961c1fa9d806037945ab866a0af6b2ff9f517d8beb5cf0c8679ec75324fd82c03e217572bdc12f374a445ce528b4ee5d8c93d3b8f254d372cabcec7ca69c4c539c0e1d02de02a0a337bdaa9910ef9402f449219b2e7376637dccdb01693e50196b7691cd8f6557e42afa7b9b7a7c925e6587613ccf007bbdf5457e67a2c2afcebd609ad8d04903cd2f748e1fd3eec0f7f812257da9d99207788e9770d12eee0240f9ae93ad9ac9b4fb63d4bf35f0c0a363bcf19eb0cf7085ead9244d4623a15deb7b9c02698d38ee78713fb67ce662ad0c76130b0b541a5120405b8683af5ec83bd8fedf72bb60491f829448cf76a73e534b"),
        testStruct(
            msg: "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            cipher2048: "18e280e8b03d8588b923842d15fddb0493285ecd7ad2d9a9878045ce615ba07cb811fd4a0737e91ece5a63b70b1edc23e0da939ec654333eb77e956108b040bd6b92927e25a6922d1b92302036985915fedf9fb38431bbce1feee3ec42ff15bc4a4b6d10b3da41ec96667b81163b30b46eef4f46fb22f187da8fd536461e5594bf557a6dfc2337883bee8d6187192a3b4bea70398b01f3ea8c1547f6c57248243365b3c46b117924d8bb6845ea382c389c648d3e65ff0b8711bbe1a6fd3bea028f5808725f198cda0407a0ff46b5af261a37184547250f496800e697290e39d46d6bce67b767d73a63bd98f699c1828180abfd51a3048d050d496236edf1e99d",
            cipher3072:
                "7f56c9312bee49fb2d93924c4be0ddc552ba918b292938136752bdced1074ce61b0af9f1cdea7dc572ceab2ae61510304ec9674175bf1f5fcbb78d466d1b8454f02c54d11e93153b9871842378a584722a5e85aa229a4c7a4399eb598f11bb931ea97d385a75627dd6698dd9255e77bd09d49b0453f2b2f7850dfea6f48ad7dbd64f046d656b0414da4e840059dbbebd27fb71c819a953440bd4bd7668953274cbedddf83dac7dea1422a6065cf4933beee13b7bf20c95ac07525f94ee38ead3809fc9eb8e4ae71ad57f72f7e8d6969aafbf8700c99f6363362dbeb0fd864c554f9a1d3cfeed9e8a94cad44a88427f856707c9f674aa2e2d29b075e246207bd692ef638c556ce50673823f5e0947845cee31ef97c1c92111d3121c7565cee925182c32ae3082ec1b0de1d6d85b61773f1b4a61a41f356f972e1358c71ea7bf9d984f603d3b69bfe0f0e995e38ef5f81f10c9e7d759eac65b7349a91b67105e30193c9491b137186bb834b8cd34171dd2b1cc4c5e923d9b29ef011937b9c59c8d",
            cipher4096:
                "3ed60cd73681d506ccfea349e5fb086eab2b679ecb796532af888088cc84d8692c6326cca3745d20a94e710335e105d2b71f6834f7cd16a1a2193a3ed88aa01b31cc5a8734178f6d9256a9a660e967ee58ba4ad63cc33ec6a08aa1c324a88f55aa700b4d5eadf46cbf7a3c5304bf883b233d5a3a2f9ae8f858959c7f832e793b5dd68f196b83702d929857a39d74a4e386f7f6636f7c03b96ffeac87625088b07a1fbeeb44fc03cb312b8f3b4308846b0566208b516687c5a786ee443ab399ea598a2631d40a7ec8671e49b6f8be46a337d9fd80c56308857247cd714205d647fdcf8019608f20bbd7816f427eb4e4384f8c10c57fb0a7a3557bd80a6744b3ce3f53ed8e32b2e384665bd274b9fd747c646111ccea90eb809e690bba31d190c6a2e2a895fcc71f521fa9c0481645348b718aaafa968bc18cc20065f25924b8f0565d1e93875fc6ec0249e5be0b1bb9d8ae054dff2a368ff4b11a3724fb8c56033ebda05246024ee0be0126217b6988242a17430284d2e9b204b9296ae22740a2e847948c60085464d8158d9ba7db29f4594dbc85482304e466936689599505576e92c6441653c2744a37b5bca6fd88c3cbf990433bd3d2f9977e474b4d09f3d489e78700df6ad9dd2b8170652d7df55557d86055b803ffca1a8c3f214369bfad683f77a4e134fcc4dba92134117323893a83c5a76c081d7f8198c2040d3fc308"),
    ]

    func test1() throws {
        let privKey2048 = try RSAPrivateKey(pem: privPem2048, format: .X509)
        let pubKey2048 = RSAPublicKey(privKey2048.n, privKey2048.e)
        let privKey3072 = try RSAPrivateKey(pem: privPem3072, format: .X509)
        let pubKey3072 = RSAPublicKey(privKey3072.n, privKey3072.e)
        let privKey4096 = try RSAPrivateKey(pem: privPem4096, format: .X509)
        let pubKey4096 = RSAPublicKey(privKey4096.n, privKey4096.e)
        for t in tests {
            let cipher2048 = Utilities.hex2bytes(t.cipher2048)
            let msg2048 = try privKey2048.decryptPKCS1(cipher: cipher2048)
            XCTAssertEqual(msg2048, Utilities.hex2bytes(t.msg))
            let cipher1 = try pubKey2048.encryptPKCS1(message: Utilities.hex2bytes(t.msg))
            let msg1 = try privKey2048.decryptPKCS1(cipher: cipher1)
            XCTAssertEqual(msg1, msg2048)
            
            let cipher3072 = Utilities.hex2bytes(t.cipher3072)
            let msg3072 = try privKey3072.decryptPKCS1(cipher: cipher3072)
            XCTAssertEqual(msg3072, Utilities.hex2bytes(t.msg))
            let cipher2 = try pubKey3072.encryptPKCS1(message: Utilities.hex2bytes(t.msg))
            let msg2 = try privKey3072.decryptPKCS1(cipher: cipher2)
            XCTAssertEqual(msg2, msg3072)
            
            let cipher4096 = Utilities.hex2bytes(t.cipher4096)
            let msg4096 = try privKey4096.decryptPKCS1(cipher: cipher4096)
            XCTAssertEqual(msg4096, Utilities.hex2bytes(t.msg))
            let cipher3 = try pubKey4096.encryptPKCS1(message: Utilities.hex2bytes(t.msg))
            let msg3 = try privKey4096.decryptPKCS1(cipher: cipher3)
            XCTAssertEqual(msg3, msg4096)
        }

    }

}