# Query CRLite data

This tool queries the published Mozilla CRLite database to determine certificate status.

It maintains a local database in your `~/.crlitedb/` folder, which is updated when older than six hours.

It works on a best-effort basis, and certificates with malformed serial numbers or other serious encoding issues might not be identified correctly, which would lead to false negatives. For a more bulletproof implementation of a CRLite decoder, you might want to consider building one atop [the rust-cascade](https://github.com/mozilla/rust-cascade) project, or simply rework the ASN.1 parsing here to reveal the exact values from the encoding without converting to intermediate Python types.

Install from [PyPi](https://pypi.org/project/moz-crlite-query/):

```sh
pip install moz_crlite_query
```

Currently, it expects PEM-formatted certificate data, and can process many at once:

```sh
for id in 77575263 1988442812 1485147627 2680822568; do
  curl --silent https://crt.sh/?d=${id} > /tmp/${id}.pem
done
moz_crlite_query /tmp/*.pem --hosts getfirefox.com
INFO:query_cli:Database was updated at 2020-04-08 16:06:39.400780, skipping.
INFO:query_cli:Status: 2195 Intermediates, Current filter: 2020-04-02T06:00:00Z-full with 18 layers and 12922536 bit-count, 2 stash files with 3307 stashed revocations, up-to-date as of 2020-04-02 12:00:00.
/tmp/1485147627.pem      Issuer: CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US
                         Enrolled in CRLite: ❌
                         Result: ❌ Not Enrolled ❌
/tmp/1988442812.pem      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                         Enrolled in CRLite: ✅
                         Revoked via CRLite filter: 2020-04-02T06:00:00Z-full
                         Result: ⛔️ Revoked ⛔️
/tmp/2680822568.pem      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                         Enrolled in CRLite: ✅
                         Result: 🐇 Too New 🐇
/tmp/77575263.pem      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                       Enrolled in CRLite: ✅
                       Result: ⏰ Expired ⏰
getfirefox.com:443      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                        Enrolled in CRLite: ✅
                        Result: 👍 Valid 👍
```

You can also pipe in PEM data:

```sh
curl --silent https://crt.sh/?d=1988442812 https://crt.sh/?d=1871771575 | moz_crlite_query -v -
INFO:query_cli:Database was updated at 2020-04-08 16:06:39.400780, skipping.
DEBUG:query_cli:Database was last updated 2:27:19.869039 ago.
INFO:query_cli:Status: 2195 Intermediates, Current filter: 2020-04-02T06:00:00Z-full with 18 layers and 12922536 bit-count, 2 stash files with 3307 stashed revocations, up-to-date as of 2020-04-02 12:00:00.
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

You can feed in files containing individual lines of the form `host:port`:

```sh
cat >/tmp/top4.txt <<EOF
apple.com
youtube.com
www.google.com:443
# This is definitely half of my top 8 spaces
www.blogger.com
EOF

moz_crlite_query --hosts mozilla.com firefox.com --hosts getfirefox.net --hosts-file /tmp/top4.txt
INFO:query_cli:Database was updated at 2020-07-16 16:10:41.545092, skipping.
INFO:query_cli:Status: 2084 Intermediates, Current filter: 2020-06-18T18:00:18+00:00Z-full with 27 layers and 41536664 bit-count, 0 stash files with 0 stashed revocations, up-to-date as of 2020-06-18 18:00:18+00:00 (28 days, 5:34:39.044502 ago).
mozilla.com:443      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                     Enrolled in CRLite: ✅
                     CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-019d2b994ec99445c735d2a6d739e43a)
                     Result: 👍 Valid 👍
firefox.com:443      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                     Enrolled in CRLite: ✅
                     CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-019d2b994ec99445c735d2a6d739e43a)
                     Result: 👍 Valid 👍
getfirefox.net:443      Issuer: CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
                        Enrolled in CRLite: ✅
                        CertID(e6426f344330d0a8eb080bbb7976391d976fc824b5dc16c0d15246d5148ff75c-019d2b994ec99445c735d2a6d739e43a)
                        Result: 👍 Valid 👍
apple.com:443      Issuer: CN=DigiCert SHA2 Extended Validation Server CA-3,OU=www.digicert.com,O=DigiCert\, Inc.,C=US
                   Enrolled in CRLite: ✅
                   CertID(9704cf37ad50839fb5a8053e32293db056835f984ba360073fcd1847e22037a3-0e7b3ab429e183d07a4fc4dbe9c4c191)
                   Result: 🐇 Too New 🐇
youtube.com:443      Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US
                     Enrolled in CRLite: ✅
                     CertID(6193e04d9fb0a0d0820885b72c7d82c5078bcc1ff59b8d907024c149d81aca3b-7e10d901f7ac03cd080000000047ef8e)
                     Result: 👍 Valid 👍
www.google.com:443      Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US
                        Enrolled in CRLite: ✅
                        CertID(6193e04d9fb0a0d0820885b72c7d82c5078bcc1ff59b8d907024c149d81aca3b-25eb382df564aeb608000000004aaba0)
                        Result: 🐇 Too New 🐇
www.blogger.com:443      Issuer: CN=GTS CA 1O1,O=Google Trust Services,C=US
                         Enrolled in CRLite: ✅
                         CertID(6193e04d9fb0a0d0820885b72c7d82c5078bcc1ff59b8d907024c149d81aca3b-be84ce8731c637490200000000715c1a)
```
