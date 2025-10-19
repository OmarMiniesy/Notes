### Using [[Suricata]]

We can create detection rules to check for [[Transport Layer Security (TLS)]] encrypted connections from [[Malware]]. The idea is to mainly scrutinize the [[Certificates]] used and check the values present in:
- Country name (2 letter code).
- State or province name.
- Locality name (usually a city name).
- Organization name.
- Organizational unit name.
- Common name (for example, fully qualified host name).
- Email address.

These values are often left blank or filled in randomly which is an indicator that something is not right.

Some important aspects to note:
- `content:"|16|"; content:"|0b|"; within:8;`: The rule looks for the hex values 16 and 0b within the first 8 bytes of the payload. These represent the handshake message (0x16) and the certificate type (0x0b) in the TLS record.
- `content:"|03 02 01 02 02 09 00|"; fast_pattern;`: The rule looks for this specific pattern of bytes in the packet, which may be characteristic of the certificates used by Dridex.
- `content:"|30 09 06 03 55 04 06 13 02|"; distance:0; pcre:"/^[A-Z]{2}/R"`;: This checks for the 'countryName' field in the certificate's subject. The content match here corresponds to an ASN.1 sequence specifying an attribute type and value for 'countryName' (OID 2.5.4.6). The following PCRE checks that the value for 'countryName' begins with two uppercase letters, which is a standard format for country codes.
- `content:"|55 04 07|"; distance:0;`: This checks for the 'localityName' field in the certificate's subject (OID 2.5.4.7).
- `content:"|55 04 0a|"; distance:0;`: This checks for the `organizationName` field in the certificate's subject (OID 2.5.4.10).
- `content:"|55 04 03|"; distance:0; byte_test:1,>,13,1,relative;`: This checks for the `commonName` field in the certificate's subject (OID 2.5.4.3). The following byte_test checks that the length of the `commonName` field is more than 13.
- Please also give this very interesting [resource on Dridex SSL certificates](https://unit42.paloaltonetworks.com/wireshark-tutorial-dridex-infection-traffic/) a look.

> The `JA3` hash can also be used to detect malware families. This hash is unique for each TLS client and combines details from the client hello packet.


---
