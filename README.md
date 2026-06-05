# draft-johani-dnsop-dnssec-alg-split

IETF Internet-Draft:
**Algorithm-Split DNSSEC: KSK/ZSK Algorithm Separation, Bounded ZSK
Cadence, and DS-Based Size Signaling**

## Summary

Post-quantum DNSSEC algorithms have much larger keys and signatures than
today's elliptic-curve algorithms. A practical transition strategy uses
a large (post-quantum) algorithm only for the key-signing key (KSK),
which signs just the apex DNSKEY RRset, while the rest of the zone is
signed with a small, traditional zone-signing key (ZSK). This draft
makes three interdependent proposals:

1. **Algorithm separation for KSK and ZSK** — relax the DNSSEC signer
   rule that requires a zone to be signed with *every* algorithm in
   the apex DNSKEY RRset, so a large KSK algorithm need not be
   applied to every RRset. Update the validator-side rule to match,
   so a conforming validator does not mark such zones Bogus.

2. **Bounded ZSK rotation cadence** — the cadence at which the ZSK is
   rolled becomes the security parameter that compensates for the
   ZSK algorithm being weaker than the KSK algorithm. Without an
   explicit cadence bound the algorithm-split profile is unsafe.

3. **DS algorithm number as a size signal** — the parent's DS RRset
   already carries the child KSK's algorithm number, so a resolver
   can recognize a likely-oversized DNSKEY RRset and query it over a
   transport suitable for large responses directly, skipping the
   truncated-UDP round trip.

This document updates RFC 4035 and RFC 6840.

## Status

Early **-00 working draft**.

## Authors

* Johan Stenstam &lt;johan.stenstam@internetstiftelsen.se&gt;

(The Swedish Internet Foundation / Internetstiftelsen)

## Current version

[draft-johani-dnsop-dnssec-alg-split-00.md](draft-johani-dnsop-dnssec-alg-split-00.md)
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
