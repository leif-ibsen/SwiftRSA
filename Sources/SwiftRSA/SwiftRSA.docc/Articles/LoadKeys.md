# Load Existing Keys

## 
### Public Key Example
```Swift
import SwiftRSA

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
```
giving:
```Swift
Sequence (2):
  Integer: 146468866012674494199005396566305180493103795313914607440885609227065639466620911741200406926829320198977634036542124958298605963326645711652241337879701684654518632735386611389097820545529978126767162719009570427221694199668818490946040417986854644616809948791703602869350011461509992533532690349796320970713
  Integer: 65537
```
### Private Key Example
```Swift
import SwiftRSA

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
```
giving:
```Swift
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
```