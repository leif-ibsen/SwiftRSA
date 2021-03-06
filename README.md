<h2><b>SwiftRSA</b></h2>
<h3><b>Contents:</b></h3>
<ul>
<li><a href="#use">Usage</a></li>
<li><a href="#basic">Basics</a>
<ul>
	<li><a href="#basic1">Creating New Keys</a></li>
	<li><a href="#basic2">Loading Existing Keys</a></li>
	<li><a href="#basic3">Encryption and Decryption</a></li>
	<li><a href="#basic4">Signing and Verifying</a></li>
</ul>
</li>
<li><a href="#perf">Performance</a></li>
<li><a href="#dep">Dependencies</a></li>
<li><a href="#ref">References</a></li>
<li><a href="#ack">Acknowledgement</a></li>
</ul>
SwiftRSA provides RSA cryptography in Swift. This encompasses:
<ul>
<li>RSA key pair creation</li>
<li>Loading existing keys from their PEM and DER encodings</li>
<li>Encryption and decryption using either the PKCS1 scheme or the OAEP scheme</li>
<li>Signature signing and verifying using either the PKCS1 scheme or the PSS scheme</li>
<li>Support for SHA1, SHA2 and SHA3 message digests</li>
</ul>
SwiftRSA requires Swift 5.0. It also requires that the Int and UInt types be 64 bit types.
<h2 id="use"><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftRSA", from: "1.0.1"),
	  ]
<h2 id="basic"><b>Basics</b></h2>

<h3 id="basic1"><b>Creating New Keys</b></h3>
<h4>Examples</h4>

	import SwiftRSA
	
	// Create a key pair with modulus size = 1024
	let (pub, priv) = try RSA.makeKeyPair(size: 1024)
	
	// See how they look
	print("Public key:\n", pub)
	print("Private key:\n", priv)
	
giving (for example):

	Public key:
	Sequence (2):
		Integer: 171253358237812531671778910624713724058916648254805696277279774146503716688113510841057236726755533384743409719012119447781138414317468691456917735176042152173382242053068370738005935216279881871488344731080784281146190232418555981064369930781879551372593036334341729194518790122071801919058147859115900850441
		Integer: 45311321411696445825758713514676800248927665812742086443844065810113678792743

	Private key:
	Sequence (9):
		Integer: 0
		Integer: 171253358237812531671778910624713724058916648254805696277279774146503716688113510841057236726755533384743409719012119447781138414317468691456917735176042152173382242053068370738005935216279881871488344731080784281146190232418555981064369930781879551372593036334341729194518790122071801919058147859115900850441
		Integer: 45311321411696445825758713514676800248927665812742086443844065810113678792743
		Integer: 584695061280334016906908582419653869380474078462173506738265501519501807337419197389310001820843363649265684565134095755443035443572908578697954503542313719653951674050695673647828817775060767181459531509458245816258177215950118920617118959314262759859870646339925135538785360703650071658070547310998336087
		Integer: 13382612000117999406264765156316869739086652743488450283117761360640268801755476473270251381994460365909400768576949457133210019867100857313588031451635521
		Integer: 12796706520095070222484462918957688688260002489347815503585927463183625906819602183307134888748685244974961739569812103528780720142075297904074163677464521
		Integer: 3256729208544643586075150908736087624897696310038023726909145466312725336259084877122515712589308623098101968585821256747176406251351820477719963859799767
		Integer: 7732534577876946504156126672827506880957981003868732483928416580372661389002341713910146649563936890820657617991361377865685231544791408634777316311012247
		Integer: 3299395382464010595538552288154453932905662599177683521047146515809523344524954262674400675308399914440853556893038003678152677499414143886031791208546986

You can also select the public exponent (or just its bitwidth) yourself, for example:

	import SwiftRSA
	
	// Create a key pair with modulus size = 1024 and public exponent = 65537
	let (pub1, priv1) = try RSA.makeKeyPair(size: 1024, exponent: RSA.F4)
	print("Public key:\n", pub1)
	
	let (pub2, priv2) = try RSA.makeKeyPair(size: 1024, expWidth: 64)
	print("Public key:\n", pub2)

giving (for example):

	Public key:
	Sequence (2):
		Integer: 118217206281438996054350875379567272643429914192458791394168929525033119986632003283395725902703772222929316561999466677326228880096771212401935014984271018664203284482282601786181002951413476203535828444866890005928775097789137634063179078567570953445296843860534263231944202911717794595174581658856633355489
		Integer: 65537

	Public key:
	Sequence (2):
		Integer: 107383747993388326460446664943087700230530763206145703774639190587970283322955235484613757107207309354545141041024709180273745428041160942928104129460424440464601559030194258787184038794097843929647759627722723588961272902877216412648664998474628650312418525039256248997901688915915828531557590622750926377141
		Integer: 13509433118470797337

Given only a private key - say 'privKey' - you can easily create the corresponding public key, for example:
	
	let pubKey = privKey.publicKey
	
<h3 id="basic2"><b>Loading Existing Keys</b></h3>
<h4>Public Key Example</h4>
	
	let pubPem =
	"""
	-----BEGIN PUBLIC KEY-----
	MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQlB5jqYD6kvsl7Ux7Mwf4JwIw
	NK5/GnSR8Gmcp2ByheYq2OmUusIbi24wXjNPSHQGfSjjBCMNyn8OhffOWVdwtuBU
	yfhEuobAaW7roHadjUo0fo/oXHJKwcRJlK8Yo55xn3IfG8UMRqOebAdfzRZJ8B8i
	YIzn3GlVUCJYM2mH2QIDAQAB
	-----END PUBLIC KEY-----
	"""
	
	let pubKey = try RSAPublicKey(pem: pubPem, format: .PKCS8)
	print(pubKey)

giving:

	Sequence (2):
		Integer: 146468866012674494199005396566305180493103795313914607440885609227065639466620911741200406926829320198977634036542124958298605963326645711652241337879701684654518632735386611389097820545529978126767162719009570427221694199668818490946040417986854644616809948791703602869350011461509992533532690349796320970713
		Integer: 65537

<h4>Private Key Example</h4>

	let privPem =
	"""
	-----BEGIN RSA PRIVATE KEY-----
	MIICXQIBAAKBgQDQlB5jqYD6kvsl7Ux7Mwf4JwIwNK5/GnSR8Gmcp2ByheYq2OmU
	usIbi24wXjNPSHQGfSjjBCMNyn8OhffOWVdwtuBUyfhEuobAaW7roHadjUo0fo/o
	XHJKwcRJlK8Yo55xn3IfG8UMRqOebAdfzRZJ8B8iYIzn3GlVUCJYM2mH2QIDAQAB
	AoGAX/SkfmkOozhXPj2LP+pcMjeP9CloVaUQF8uoap896bHcD742x2ubvRxKFwpf
	RIwqhImz86yFi+Sqyz2qoU3MwYNiLu3Trm8EJ6KimLUbl4GKVDDxNwX0LYslR2+T
	nJNeOJ4w2a3l0BgJIBNfWu8MX+zRXwC4O1HauLqTDYiCaAECQQDogtEtXwviaoA1
	nxPAghC9y/dZ3+5pUxPvqIhpGWWbBk48ZWomevYnXtGviaXf6eJbMaArr71ZRFt1
	B6IpiaaBAkEA5aZc+maL2FfVkTWnjBjIrbfCIjaOnXSrrY6DKZ96w8KteqRN2wXe
	6m2bINuvCahhUoShfHLTcjJAM0aF6n4lWQJBAKMnyOjxnUFQQo9eBVo86sqEahnj
	DUVTStYNiUtWyvmxvwyajZZbCogt/S4UhRVO5cvgUujU9SXC1fqVVLGZKgECQQCR
	8XzrQRokfgVih/eXh/SYucwtFADkPc4QuR3P6OMK34CCDULRK1T0JH3Oju4ZNCHN
	YC6EOTD5RMgaDfpzAIHZAkB1kVpFR3C0kIJCN2EkTM7GWm5IrplmNEtnVhD6ytkW
	L6W9HMUQjDIsL7PBRPgHdzosfQl/Y+XI072M6O+sKt4E
	-----END RSA PRIVATE KEY-----",
	"""
	
	let privKey = try RSAPrivateKey(pem: privPem, format: .X509)
	print(privKey)

giving:

	Sequence (9):
		Integer: 0
		Integer: 146468866012674494199005396566305180493103795313914607440885609227065639466620911741200406926829320198977634036542124958298605963326645711652241337879701684654518632735386611389097820545529978126767162719009570427221694199668818490946040417986854644616809948791703602869350011461509992533532690349796320970713
		Integer: 65537
		Integer: 67382338378048064453667587873630181300137013118002432432712835775150358269658673558405057735994995254576432644181837244498572864096592279266903830463295620222822037054672106475644379520038123845082875773066220624387732263153950916669984286952068290656491939858632385150729955503402950713758598741708322793473
		Integer: 12177589402871783125863782303783517781619311199989346703617378950359712439763268604247040370157556242150941561186815774508253599534795581134503270221981313
		Integer: 12027738919997863988275089788715420537388543975016911924817786398588536130594151706147265632096853121288313983522998073377376185111770203718840378890003801
		Integer: 8545142155717648998157126822808435170073529204344264708576163436976707137644890620139965096705764628592054877639490422785381792505091462612166202160130561
		Integer: 7643671487541252075128083595681959045450592306872138864408440815338113451990720118548720056017239660779971452763314566704218086481226135079206905112986073
		Integer: 6157524461724051685386054557693317486410709346450446932377906107204884860836696932100787383589486062483638068661928961730224364153568746524241890686721540

<h3 id="basic3"><b>Encryption and Decryption</b></h3>

You need a public key - say 'pubKey' - to encrypt a message and the corresponding private key - say 'privKey' - to decrypt it.
<h4>PKCS1 Example</h4>

	let pkcs1Cipher = try pubKey.encryptPKCS1(message: [1, 2, 3])
	let clearTekst = try privKey.decryptPKCS1(cipher: pkcs1Cipher)

<h4>OAEP Example</h4>

	let oaepCipher = try pubKey.encryptOAEP(message: [1, 2, 3], mda: .SHA3_256, label: [4, 5, 6])
	let clearTekst = try privKey.decryptOAEP(cipher: oaepCipher, mda: .SHA3_256, label: [4, 5, 6])

<h3 id="basic4"><b>Signing and Verifying</b></h3>

You need a private key - say 'privKey' - to sign a message and the corresponding public key - say 'pubKey' - to verify the signature.
<h4>PKCS1 Example</h4>

    let pkcs1Signature = try privKey.signPKCS1(message: [1, 2, 3], mda: .SHA3_256)
    let ok = pubKey.verifyPKCS1(signature: pkcs1Signature, message: [1, 2, 3], mda: .SHA3_256)

<h4>PSS Example</h4>

    let pssSignature = try privKey.signPSS(message: [1, 2, 3], mda: .SHA3_256)
    let ok = pubKey.verifyPSS(signature: pssSignature, message: [1, 2, 3], mda: .SHA3_256)

<h2 id="perf"><b>Performance</b></h2>
To assess the performance of SwiftRSA, the keypair generation time, the signature generation and verification time,
and the encryption and decryption time was measured on an iMac 2021, Apple M1 chip.
The results are shown in the table below - units are milliseconds. The rows mean:
<ul>
<li>Make Keypair: The time it takes to generate a public/private keypair -
the timing may vary from one test to another due to the randomness involved in the key pair generation</li>
<li>Sign PKCS1: The time it takes to sign a short message using the PKCS1 scheme</li>
<li>Verify PKCS1: The time it takes to verify a signature for a short message using the PKCS1 scheme</li>
<li>Sign PSS: The time it takes to sign a short message using the PSS scheme</li>
<li>Verify PSS: The time it takes to verify a signature for a short message using the PSS scheme</li>
<li>Encrypt PKCS1: The time an encryption operation takes using the PKCS1 scheme</li>
<li>Decrypt PKCS1: The time a decryption operation takes using the PKCS1 scheme</li>
<li>Encrypt OAEP: The time an encryption operation takes using the OAEP scheme</li>
<li>Decrypt OAEP: The time a decryption operation takes using the OAEP scheme</li>
</ul>
<table width="85%">
<tr><th align="left" width="20%">Modulus size</th><th align="right" width="20%">1024</th><th align="right" width="20%">2048</th><th align="right" width="20%">3072</th><th align="right" width="20%">4096</th></tr>
<tr><td align="left">Make Keypair</td><td align="right">~ 50 mSec</td><td align="right">~ 250 mSec</td><td align="right">~ 1500 mSec</td><td align="right">~ 2400 mSec</td></tr>
<tr><td align="left">Sign PKCS1</td><td align="right">1.6 mSec</td><td align="right">5.5 mSec</td><td align="right">13 mSec</td><td align="right">25 mSec</td></tr>
<tr><td align="left">Verify PKCS1</td><td align="right">0.081 mSec</td><td align="right">0.18 mSec</td><td align="right">0.35 mSec</td><td align="right">0.58 mSec</td></tr>
<tr><td align="left">Sign PSS</td><td align="right">1.6 mSec</td><td align="right">5.5 mSec</td><td align="right">12 mSec</td><td align="right">25 mSec</td></tr>
<tr><td align="left">Verify PSS</td><td align="right">0.095 mSec</td><td align="right">0.21</td> mSec</td><td align="right">0.39 mSec</td><td align="right">0.63 mSec</td></tr>
<tr><td align="left">Encrypt PKCS1</td><td align="right">0.084 mSec</td><td align="right">0.18 mSec</td><td align="right">0.35 mSec</td><td align="right">0.58 mSec</td></tr>
<tr><td align="left">Decrypt PKCS1</td><td align="right">1.5 mSec</td><td align="right">5.4 mSec</td><td align="right">13 mSec</td><td align="right">25 mSec</td></tr>
<tr><td align="left">Encrypt OAEP</td><td align="right">0.099 mSec</td><td align="right">0.22 mSec</td><td align="right">0.40 mSec</td><td align="right">0.64 mSec</td></tr>
<tr><td align="left">Decrypt OAEP</td><td align="right">1.5 mSec</td><td align="right">5.5 mSec</td><td align="right">13 mSec</td><td align="right">25 mSec</td></tr>
</table>
The SHA2 256 message digest was used in the measurements, the public exponent was 65537.
<h2 id="dep"><b>Dependencies</b></h2>

The SwiftRSA package depends on the ASN1 and BigInt packages

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.0.1"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.2.12"),
    ],
<h2 id="ref"><b>References</b></h2>

SwiftRSA is implemented in accordance with algorithms in the following papers.
There are references in the source code where appropriate.

<ul>
<li>[NIST] - NIST Special Publication 800-56B Revision 2, March 2019</li>
<li>[PKCS1] - RSA Cryptography Specification Version 2.2, November 2016</li>
</ul>

<h2 id="ack"><b>Acknowledgement</b></h2>

Most of the unit test cases in the project come from Project Wycheproof - https://github.com/google/wycheproof
