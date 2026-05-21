---
title: "Large Key-Signing Keys in DNSSEC: Algorithm Separation and DS-Based TCP Signaling"
abbrev: "Large KSKs in DNSSEC"
category: std
docname: draft-johani-dnsop-dnssec-large-ksk-00
submissiontype: IETF
ipr: trust200902
area: "Internet"
workgroup: "DNSOP Working Group"
updates: 4035, 6840
keyword:
 - DNSSEC
 - post-quantum
 - KSK
 - ZSK
 - TCP
 - DNSKEY
venue:
  group: "Domain Name System Operations"
  type: "Working Group"
  mail: "dnsop@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/dnsop/"

author:
 -
    fullname: Johan Stenstam
    organization: The Swedish Internet Foundation
    email: johan.stenstam@internetstiftelsen.se

normative:
  RFC4035:
  RFC6840:

informative:
  RFC6781:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: "https://csrc.nist.gov/pubs/fips/204/final"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    date: 2024-08
    seriesinfo:
      FIPS: "204"
  FIPS205:
    title: "Stateless Hash-Based Digital Signature Standard"
    target: "https://csrc.nist.gov/pubs/fips/205/final"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    date: 2024-08
    seriesinfo:
      FIPS: "205"

--- abstract

Post-quantum DNSSEC signature algorithms have much larger keys and
signatures than the elliptic-curve algorithms in common use today.
Signing an entire zone with such an algorithm inflates every signature
in the zone. A natural transition strategy applies a large algorithm
only to the key-signing key (KSK), which signs only the apex DNSKEY
RRset, while the bulk of the zone continues to be signed with a small,
traditional zone-signing key (ZSK).

This document makes two complementary proposals that make this pattern
practical. First, it relaxes the DNSSEC signing rule that requires a
zone to be signed with every algorithm present in the apex DNSKEY RRset,
so that an algorithm used only by a key-signing key need not be applied
to the rest of the zone. Second, it observes that the parent's DS RRset
already carries the child KSK's algorithm number, and specifies how a
resolver can use that number to recognize a likely-oversized DNSKEY
RRset and query it over TCP directly, avoiding a truncated UDP response
and the subsequent retry. This document updates RFC 4035 and RFC 6840.

--- middle

# Introduction

DNSSEC signature and key sizes are about to grow substantially. The
post-quantum signature algorithms standardized by NIST -- ML-DSA
{{FIPS204}} and SLH-DSA {{FIPS205}}, with FN-DSA and others to follow --
have public keys and signatures that are one to two orders of magnitude
larger than the elliptic-curve algorithms (ECDSA, Ed25519) in common use
today. Signing an entire zone with such an algorithm inflates every
RRSIG in the zone and every signed response.

A natural transition strategy is to apply a large (for example,
post-quantum) algorithm only where its cost is bounded -- the
key-signing key (KSK), which signs only the apex DNSKEY RRset -- while
continuing to sign the bulk of the zone with a small, traditional
zone-signing key (ZSK). The DNSKEY RRset is then the only large object
in the zone; ordinary query responses remain small.

This document makes two proposals that, together, make this deployment
pattern practical:

1. Distinct algorithms for the KSK and the ZSK ({{p-algsep}}). DNSSEC's
   current signing rules require a zone to be signed with every
   algorithm present in the apex DNSKEY RRset. This document relaxes
   that rule for an algorithm used solely by a key-signing key, so that
   a large KSK algorithm need not be applied to every RRset in the zone.

2. Using the DS algorithm number to signal large DNSKEY RRsets
   ({{p-dssignal}}). Because the parent's DS RRset carries the child
   KSK's algorithm number, a resolver can recognize from the DS alone
   that the child's DNSKEY RRset is likely to exceed common UDP
   response-size limits, and query it over TCP directly -- avoiding a
   truncated UDP response and the consequent retry.

The two proposals are independent in principle but complementary in
practice: the first creates a single large object (the DNSKEY RRset) in
an otherwise small zone, and the second optimizes the retrieval of
exactly that object.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses "key-signing key" (KSK) and "zone-signing key" (ZSK)
in the operational sense of {{RFC6781}}: a KSK is a key whose role is to
sign the apex DNSKEY RRset and which is referenced by a DS record at the
parent, while a ZSK signs the other RRsets of the zone. This
KSK/ZSK distinction is operational; the DNSSEC protocol itself does not
require it, and the Secure Entry Point (SEP) bit is advisory rather than
normative.

# Proposal 1: Distinct Algorithms for the KSK and the ZSK {#p-algsep}

## The Current Rule

Section 2.2 of {{RFC4035}}, as restated in Section 5.11 of {{RFC6840}},
governs which algorithms must be used to sign a zone. On the signer
side: "The zone MUST also be signed with each algorithm (though not each
key) present in the DNSKEY RRset." In other words, every RRset in the
zone must carry a signature from each algorithm appearing in the apex
DNSKEY RRset.

If the apex DNSKEY RRset contains a large-algorithm KSK and a
small-algorithm ZSK, this rule requires every RRset in the zone to carry
a large-algorithm signature, which defeats the purpose of confining the
large algorithm to the KSK.

The validator side of the same rule already accommodates the desired
pattern. Per Section 5.11 of {{RFC6840}}, validators "SHOULD accept any
single valid path" and "MUST NOT insist that all algorithms signaled in
the DNSKEY RRset work." A validator that supports the ZSK algorithm can
therefore validate the zone's RRsets using ZSK signatures alone. The
obstacle to the deployment pattern is solely the signer-side
requirement.

## The Change

This document updates the signer-side requirement as follows: an
algorithm that is present in the apex DNSKEY RRset solely by virtue of
one or more key-signing keys -- keys that sign only the apex DNSKEY
RRset -- does not, by its presence, require the other RRsets of the zone
to be signed with that algorithm. Concretely:

* The apex DNSKEY RRset MUST be signed by each algorithm appearing in
  the DS RRset at the parent (unchanged). In the deployment of interest
  this includes the large KSK algorithm.

* Every other RRset in the zone MUST be signed with each algorithm
  present in the apex DNSKEY RRset, except algorithms used only by
  key-signing keys as described above. In the deployment of interest
  this means every non-DNSKEY RRset is signed with the ZSK algorithm
  only.

> **Editorial note (open issue):** The precise normative definition of
"an algorithm used only by a key-signing key" needs care, because the
KSK/ZSK distinction is not normative in DNSSEC (the SEP bit is
advisory). A candidate definition: an algorithm for which every DNSKEY
in the apex DNSKEY RRset that uses that algorithm has the SEP bit set,
and which is used to sign only the apex DNSKEY RRset. Edge cases -- such
as an algorithm shared by both a KSK and a ZSK -- need to be worked out
before this text is normative.

## Validator Behavior

Validator behavior is unchanged from {{RFC6840}}. A validator that
supports the ZSK algorithm validates non-DNSKEY RRsets using ZSK
signatures. To establish trust in the apex DNSKEY RRset it follows the
DS-based chain of trust, which requires support for the KSK algorithm
(the algorithm in the parent's DS RRset); see {{security}}.

# Proposal 2: DS Algorithm Number as a Signal to Use TCP for the DNSKEY RRset {#p-dssignal}

## The Truncation Round Trip

When a resolver validates a delegation, it retrieves the child's DNSKEY
RRset. If the KSK uses a large algorithm, the DNSKEY RRset together with
its RRSIG commonly exceeds the EDNS(0) UDP response size that has become
a de facto ceiling in much of the deployed base (frequently 1232
octets). A UDP query for such a DNSKEY RRset returns a truncated
response with the TC bit set, and the resolver must repeat the query
over TCP. This costs an extra round trip and a TCP handshake on the
first validation of the zone.

## Resolver Behavior

A resolver that has obtained a child's DS RRset MAY use the algorithm
number(s) in that DS RRset to decide how to query the child DNSKEY
RRset. If the resolver recognizes a DS algorithm as one whose keys and
signatures are large enough that the DNSKEY RRset is likely to exceed
its UDP response-size limit, the resolver SHOULD query the DNSKEY RRset
over TCP directly, rather than first attempting UDP and incurring a
truncated response.

This is a local optimization. It changes neither the wire format nor the
validation outcome. A resolver that does not implement it simply
experiences the existing UDP-then-TCP behavior.

## Identifying Large Algorithms

To apply {{p-dssignal}} a resolver needs to map an algorithm number to
the property "the DNSKEY RRset is likely too large for UDP." There are
two ways to provide this mapping:

1. Implementation knowledge: the resolver hard-codes which algorithms
   are large.

2. A registry annotation: a column in the "DNS Security Algorithm
   Numbers" registry that records, for each algorithm, whether its
   typical DNSKEY/RRSIG sizes are large for UDP purposes (or records
   representative key and signature sizes from which a resolver can
   decide).

This document recommends approach 2 so that resolvers need not hard-code
per-algorithm knowledge; see {{iana}}.

> **Editorial note (open issue):** Whether the annotation should be a
boolean "large" flag or numeric size hints (and the exact threshold
semantics relative to a resolver's configured UDP buffer size) is open.

## Limitations

The DS algorithm number reflects the KSK algorithm only. The signal is
reliable when the KSK is the large component of the DNSKEY RRset, which
is exactly the deployment of {{p-algsep}}. If a zone instead paired a
small KSK algorithm with a large ZSK algorithm, the DNSKEY RRset could
still be large while the DS signaled a small algorithm; the signal would
be a false negative and the resolver would fall back to the existing
UDP-then-TCP behavior. A false positive (treating a small DNSKEY RRset
as large) causes only an unnecessary use of TCP and never affects
correctness.

# Operational Considerations

The large DNSKEY RRset is retrieved and validated once and then cached;
subsequent queries for ordinary zone data return small,
ZSK-signed responses that fit comfortably in UDP. The large object is
thus a one-time-per-cache cost, which {{p-dssignal}} further reduces by
avoiding the truncated-UDP round trip.

Rolling a large KSK transiently enlarges the DNSKEY RRset further, as it
must hold both the outgoing and incoming KSKs during the rollover.
Operators should account for this when sizing transport expectations.

A validator that does not support the KSK algorithm cannot follow the
DS-based chain of trust and treats the delegation as insecure, exactly
as for any rollout of a new algorithm. Deploying a large/post-quantum
KSK therefore has the same backward-compatibility profile as introducing
any new DNSSEC algorithm.

# Security Considerations {#security}

Proposal 1 narrows the set of validators that can cryptographically
validate the zone. Because the parent's DS RRset references only the
(large) KSK algorithm, only a validator that supports that algorithm can
establish trust in the apex DNSKEY RRset, and hence validate any data in
the zone. Such a validator must also support the ZSK algorithm in order
to validate non-DNSKEY RRsets, since under Proposal 1 those RRsets are
signed with the ZSK algorithm only. The safety of the pattern therefore
rests on the assumption that any validator supporting the KSK algorithm
also supports the ZSK algorithm. During the transition to post-quantum
algorithms this assumption holds, because the traditional ZSK algorithms
(ECDSA, Ed25519) are universally supported; it should be revisited if
that ceases to be true.

A validator that does not support the KSK algorithm treats the
delegation as insecure (Section 5.2 of {{RFC4035}}), as it would for any
algorithm it does not implement. Proposal 1 does not change this
behavior.

Signing zone data with a traditional (non-post-quantum) ZSK does not
provide post-quantum integrity for that data. An adversary able to break
the ZSK algorithm can forge zone data regardless of the KSK algorithm.
The value of a large or post-quantum KSK combined with a traditional ZSK
is operational and transitional -- exercising large-key handling,
transport, and the chain of trust, and protecting the longer-lived
trust anchor -- and not the provision of post-quantum protection for the
bulk of the zone.

Proposal 2 is a transport optimization with no effect on validation. A
misjudgment about an algorithm's size results only in an unnecessary TCP
query, or in a fallback to the existing UDP-then-TCP behavior; it cannot
affect whether data validates.

# IANA Considerations {#iana}

Proposal 1 ({{p-algsep}}) requires no IANA action; it updates the
signing rules of {{RFC4035}} and {{RFC6840}}.

For Proposal 2 ({{p-dssignal}}), IANA is requested to add an annotation
to the "DNS Security Algorithm Numbers" registry indicating, for each
algorithm, whether its typical DNSKEY and RRSIG sizes are large for the
purpose of UDP transport (or recording representative key and signature
sizes).

> **Editorial note (open issue):** The exact form of the annotation (a
new column, its permitted values, and the registration policy for
populating it) is to be specified.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
