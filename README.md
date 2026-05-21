# draft-johani-dnsop-dnssec-large-ksk

IETF Internet-Draft:
**Large Key-Signing Keys in DNSSEC: Algorithm Separation and DS-Based
TCP Signaling**

## Summary

Post-quantum DNSSEC algorithms have much larger keys and signatures than
today's elliptic-curve algorithms. A practical transition strategy uses
a large (post-quantum) algorithm only for the key-signing key (KSK),
which signs just the apex DNSKEY RRset, while the rest of the zone is
signed with a small, traditional zone-signing key (ZSK). This draft
makes two complementary proposals:

1. **Algorithm separation for KSK and ZSK** — relax the DNSSEC signer
   rule that requires a zone to be signed with *every* algorithm in the
   apex DNSKEY RRset, so a large KSK algorithm need not be applied to
   every RRset. (Validators already accept any single valid path per
   RFC 6840 §5.11, so only the signer-side rule changes.)

2. **DS algorithm number as a TCP hint** — the parent's DS RRset already
   carries the child KSK's algorithm number, so a resolver can recognize
   a likely-oversized DNSKEY RRset and query it over TCP directly,
   skipping the truncated-UDP round trip.

This document updates RFC 4035 and RFC 6840.

## Status

Early **-00 working draft**. Several design points are still open and
marked with `[[ EDITORIAL NOTE ]]` in the text — notably the precise
normative definition of "an algorithm used only by a key-signing key,"
and the form of the IANA registry annotation for algorithm size.

## Authors

* Johan Stenstam &lt;johan.stenstam@internetstiftelsen.se&gt;

(The Swedish Internet Foundation / Internetstiftelsen)

## Current version

[draft-johani-dnsop-dnssec-large-ksk-00.md](draft-johani-dnsop-dnssec-large-ksk-00.md)
— status: Internet-Draft, Standards Track, -00.

## Building the draft

The source is [kramdown-rfc](https://github.com/cabo/kramdown-rfc)
markdown. To produce text and HTML renderings:

```
make
```

(Requires `kramdown-rfc` and `xml2rfc` in `$PATH`.)

## License

This document is subject to the BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents
(https://trustee.ietf.org/license-info) in effect on the date of
publication of this document.
