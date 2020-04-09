# Query CRLite data

This tool queries the published Mozilla CRLite database to determine certificate status.

It maintains a local database in your `~/.crlitedb/` folder, which is updated when older than six hours.

Install from [PyPi](https://pypi.org/project/moz-crlite-query/):

```sh
pip install moz_crlite_query
```

Currently, it expects PEM-formatted certificate data, and can process many at once:

```sh
for id in 77575263 1988442812 1485147627 2680822568; do
  curl --silent https://crt.sh/?d=${id} > /tmp/${id}.pem
done
moz_crlite_query /tmp/*.pem
/tmp/1485147627.pem      Issuer: CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
                         Enrolled in CRLite: ❌
                         CertID(60b87575447dcba2a36b7d11ac09fb24a9db406fee12d2cc90180517616e8a18-0313e984aa6b184b7fcc9fcd54ed5df8f1bf)
                         Result: ❌ Not Enrolled ❌
/tmp/1988442812.pem      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                         Enrolled in CRLite: ✅
                         CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-0371b58a86f6ce9c3ecb7bf42f9208fc)
                         Revoked via CRLite filter: 2020-04-02T06:00:00Z-full
                         Result: ⛔️ Revoked ⛔️
/tmp/2680822568.pem      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                         Enrolled in CRLite: ✅
                         CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-019d2b994ec99445c735d2a6d739e43a)
                         Result: 🐇 Too New 🐇
/tmp/77575263.pem      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                       Enrolled in CRLite: ✅
                       CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-0ac735b4a8163c96c73b4c7cb7437aa2)
                       Result: ⏰ Expired ⏰
```

You can also pipe in PEM data:

```sh
curl --silent https://crt.sh/?d=1988442812 https://crt.sh/?d=1871771575 | moz_crlite_query -
<stdin>      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
             Enrolled in CRLite: ✅
             CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-0371b58a86f6ce9c3ecb7bf42f9208fc)
             Revoked via CRLite filter: 2020-04-02T06:00:00Z-full
             Result: ⛔️ Revoked ⛔️
<stdin>      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
             Enrolled in CRLite: ✅
             CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-0f7d9e589e0dd146f55bc6530139d3a6)
             Result: 👍 Valid 👍
```