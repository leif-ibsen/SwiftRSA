# Performance

## 

To assess the performance of SwiftRSA, the keypair generation time, the signature generation and verification time,
and the encryption and decryption time was measured on an iMac 2021, Apple M1 chip.

The results are shown in the table below - units are milliseconds. The rows mean:

* Make Keypair: The time it takes to generate a public/private keypair -
the timing may vary from one test to another due to the randomness involved in the key pair generation
* Sign PKCS1: The time it takes to sign a short message using the PKCS1 scheme
* Verify PKCS1: The time it takes to verify a signature for a short message using the PKCS1 scheme
* Sign PSS: The time it takes to sign a short message using the PSS scheme
* Verify PSS: The time it takes to verify a signature for a short message using the PSS scheme
* Encrypt PKCS1: The time an encryption operation takes using the PKCS1 scheme
* Decrypt PKCS1: The time a decryption operation takes using the PKCS1 scheme
* Encrypt OAEP: The time an encryption operation takes using the OAEP scheme
* Decrypt OAEP: The time a decryption operation takes using the OAEP scheme

| Modulus size  | 1024       | 2048        | 3072        | 4096        |
|:--------------|-----------:|------------:|------------:|------------:|
| Make Keypair  | ~ 50 mSec  | ~ 250 mSec  | ~ 1500 mSec | ~ 2400 mSec |
| Sign PKCS1    | 1.6 mSec   | 5.5 mSec    | 13 mSec     | 25 mSec     |
| Verify PKCS1  | 0.081 mSec | 0.18 mSec   | 0.35 mSec   | 0.58 mSec   |
| Sign PSS      | 1.6 mSec   | 5.5 mSec    | 12 mSec     | 25 mSec     |
| Verify PSS    | 0.095 mSec | 0.21 mSec   | 0.39 mSec   | 0.63 mSec   |
| Encrypt PKCS1 | 0.084 mSec | 0.18 mSec   | 0.35 mSec   | 0.58 mSec   |
| Decrypt PKCS1 | 1.5 mSec   | 5.4 mSec    | 13 mSec     | 25 mSec     |
| Encrypt OAEP  | 0.099 mSec | 0.22 mSec   | 0.40 mSec   | 0.64 mSec   |
| Decrypt OAEP  | 1.5 mSec   | 5.5 mSec    | 13 mSec     | 25 mSec     |

The SHA2 256 message digest was used in the measurements, the public exponent was 65537.
