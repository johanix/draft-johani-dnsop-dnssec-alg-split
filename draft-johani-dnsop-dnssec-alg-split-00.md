---
title: "Algorithm-Split DNSSEC: KSK/ZSK Algorithm Separation with Bounded ZSK Cadence"
abbrev: "Algorithm-Split DNSSEC"
category: std
docname: draft-johani-dnsop-dnssec-alg-split-00
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
 - DNSKEY
 - transport
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

informative:
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

Post-quantum DNSSEC signature algorithms have much larger keys and/or
signatures than the elliptic-curve algorithms in common use today.
Signing an entire zone with such an algorithm inflates every signature
in the zone. A natural transition strategy applies a large algorithm
only to the key-signing key (KSK), which signs only the apex DNSKEY
RRset, while the bulk of the zone continues to be signed with a smaller
zone-signing key (ZSK).

This document specifies the three changes that, taken together, make
this pattern safe and practical: (1) it relaxes the DNSSEC signing rule
that requires a zone to be signed with every algorithm present in the
apex DNSKEY RRset, so that an algorithm used only by a key-signing key
need not be applied to the rest of the zone; (2) it imposes a bounded
ZSK rotation cadence as the security parameter that compensates for the
asymmetric strength of the two algorithms; and (3) it specifies how a
resolver can use the algorithm number in the parent's DS RRset to
recognize a likely-oversized DNSKEY RRset and select a transport
suitable for large responses, avoiding the truncate-then-retry round
trip. The three parts are interdependent and constitute a single
proposal. This document updates RFC 4035 and RFC 6840.

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
continuing to sign the bulk of the zone with a smaller ZSK. The DNSKEY
RRset is then the only large object in the zone; ordinary query
responses remain small.

Asymmetric key strength between the KSK and ZSK is already common
operational practice. Operators routinely deploy RSA zones with a
longer (i.e. stronger) KSK and a shorter ZSK, trading
larger DNSKEY-RRset signatures for smaller signatures on the rest of
the zone. The KSK/ZSK strength asymmetry proposed by this document is
the same operational pattern; the only difference is that the
asymmetry crosses the algorithm-number boundary rather than a
key-length boundary within a single algorithm. It is that crossing --
not the strength asymmetry itself -- that interacts with the
completeness rule of {{!RFC4035}} and motivates the updates in this
document.

This document specifies three changes that together enable this
deployment pattern:

1. Distinct algorithms for the KSK and the ZSK ({{p-algsep}}). DNSSEC's
   current signing rules require a zone to be signed with every
   algorithm present in the apex DNSKEY RRset. This document relaxes
   that rule for an algorithm used solely by a key-signing key, so that
   a large KSK algorithm need not be applied to every RRset in the zone.

2. A bounded ZSK rotation cadence ({{p-zskcadence}}). When the KSK and
   ZSK use different algorithms of different strengths, the security of
   the zone depends not on algorithmic completeness but on limiting the
   useful lifetime of any ZSK an adversary might break. This document
   requires the ZSK to be rolled at a cadence appropriate to the threat
   estimate against the ZSK algorithm, and expects that cadence to
   tighten over time.

3. Using the DS algorithm number to signal a large DNSKEY RRset
   ({{p-dssignal}}). Because the parent's DS RRset carries the child
   KSK's algorithm number, a resolver can recognize from the DS alone
   that the child's DNSKEY RRset is likely to exceed common UDP
   response-size limits, and query it over a transport suitable for
   large responses (TCP, DoT, DoQ, or another) directly -- avoiding a
   truncated UDP response and the consequent retry.

The three parts are interdependent and constitute a single proposal.
Part 1 makes the deployment pattern possible; part 2 is the security
parameter that makes part 1 safe; part 3 makes the resulting transport
profile efficient. Implementations that adopt only some of these
changes either lose efficiency (omitting part 3) or weaken the security
argument (omitting part 2).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses "key-signing key" (KSK) and "zone-signing key" (ZSK)
in the operational sense of {{?RFC6781}}: a KSK is a key whose role is to
sign the apex DNSKEY RRset and which is referenced by a DS record at the
parent, while a ZSK signs the other RRsets of the zone. This
KSK/ZSK distinction is operational; the DNSSEC protocol itself does not
require it, and the Secure Entry Point (SEP) bit is advisory rather than
normative. The normative conditions in this document do not rely on the
SEP bit; instead, they are expressed in terms of the algorithms present
in the parent DS RRset and the apex DNSKEY RRset (see {{p-algsep}}).

# Part 1: Distinct Algorithms for the KSK and the ZSK {#p-algsep}

## The Current Rule

Section 2.2 of {{!RFC4035}}, as restated in Section 5.11 of {{!RFC6840}},
governs which algorithms must be used to sign a zone. On the signer
side: "The zone MUST also be signed with each algorithm (though not each
key) present in the DNSKEY RRset." In other words, every RRset in the
zone must carry a signature from each algorithm appearing in the apex
DNSKEY RRset.

If the apex DNSKEY RRset contains a large-algorithm KSK and a
small-algorithm ZSK, this rule requires every RRset in the zone to carry
a large-algorithm signature, which defeats the purpose of confining the
large algorithm to the KSK.

## The Change (Signer Side)

This document updates the signer-side requirement of {{!RFC4035}} and
{{!RFC6840}} as follows. A zone MAY be signed under the following
*algorithm-split profile*. Let K be the set of algorithms appearing in
the parent DS RRset for the zone, and let Z be a non-empty set of
algorithms disjoint from K (K and Z share no algorithm). The profile
holds when:

* The apex DNSKEY RRset of the zone contains at least one key of each
  algorithm in K and at least one key of each algorithm in Z.

* The apex DNSKEY RRset MUST be signed by every algorithm in K. It MAY
  additionally be signed by one or more algorithms in Z.

* Every non-DNSKEY authoritative RRset in the zone MUST be signed by
  every algorithm in Z and MUST NOT be required to be signed by any
  algorithm in K.

Within this profile, the algorithms in K play the role of KSK
algorithms and the algorithms in Z play the role of ZSK algorithms.
K and Z are disjoint by definition; no single algorithm can
simultaneously serve as a KSK algorithm and a ZSK algorithm in this
profile. The profile is defined entirely in terms of the contents of
the parent DS RRset and the apex DNSKEY RRset, so that compliance can
be checked without reference to the (advisory) SEP bit.

The common steady-state case has |K| = |Z| = 1 (a single KSK algorithm
A and a single ZSK algorithm B, with A != B). |K| > 1 corresponds to
a KSK-algorithm rollover (the zone is transitioning between two KSK
algorithms, both of which appear in the parent DS RRset and the apex
DNSKEY RRset during the rollover window). |Z| > 1 corresponds to a
ZSK-algorithm rollover (every non-DNSKEY RRset carries a signature
from each old and new ZSK algorithm during the rollover window). A
ZSK-algorithm rollover under this profile is no easier and no harder
than the existing ZSK-algorithm rollover for an all-ZSK zone, and its
size cost is the same.

The profile is defined in terms of algorithm separation and
strength asymmetry alone; it does not assume any particular
character for either algorithm. In the most-discussed near-term
deployment, the KSK algorithm is post-quantum and the ZSK
algorithm is a classical elliptic-curve algorithm, but the profile
applies equally when both KSK and ZSK algorithms are
post-quantum -- in particular when the ZSK algorithm is a
post-quantum scheme whose signatures are small enough to be
acceptable on every RRset in the zone but whose long-term security
margin is insufficient for a KSK that rolls slowly. As the set of
standardized post-quantum signature algorithms grows, the profile
is expected to admit an increasing range of ZSK choices whose
strength against future cryptanalysis informs only the cadence
requirement of {{p-zskcadence}}, not the structural shape of the
profile itself.

A zone that does not match this profile remains subject to the existing
completeness rule of {{!RFC4035}} Section 2.2 and {{!RFC6840}} Section
5.11.

## The Change (Validator Side)

This document also updates the validator-side behavior of {{!RFC4035}}
and {{!RFC6840}}. When a validator processes a zone whose parent DS and
apex DNSKEY RRsets match the algorithm-split profile of the preceding
section, with KSK-algorithm set K and ZSK-algorithm set Z, the
validator:

* MUST validate the apex DNSKEY RRset using a signature of some
  algorithm in K (the algorithms present in the parent DS RRset), as
  required by the existing chain-of-trust rules.

* MUST validate non-DNSKEY RRsets of the zone using signatures of some
  algorithm in Z.

* MUST NOT treat the zone as Bogus solely because non-DNSKEY RRsets lack
  signatures of any algorithm in K.

A validator that supports some algorithm in K but no algorithm in Z
treats the zone as it would any zone whose data signatures are in an
unsupported algorithm (see Section 5.2 of {{!RFC4035}}). A validator
that supports no algorithm in K treats the delegation as Insecure, as
today.

The validator-side update is essential. Without it, a strict reading
of the existing completeness rules would cause a conforming validator
to mark every algorithm-split zone as Bogus. Implementations that
support this document MUST therefore implement the relaxation on both
the signer and validator sides.

# Part 2: Bounded ZSK Rotation Cadence {#p-zskcadence}

## Why a Cadence Bound Is Required

Under the algorithm-split profile of {{p-algsep}}, the KSK and ZSK
algorithms are not peers. For readability the rest of this section
describes the steady-state case |K| = |Z| = 1 with KSK algorithm A and
ZSK algorithm B; the argument extends directly to rollover windows
where K or Z is larger, in which case every algorithm in K plays the
role of A and every algorithm in Z plays the role of B.

The KSK algorithm A and the ZSK algorithm B occupy distinct positions
in a fixed chain of trust:

1. The parent DS RRset, validated by the parent's own chain of trust,
   authenticates the child's KSK (algorithm A).
2. The KSK signs the apex DNSKEY RRset, authenticating the ZSK
   (algorithm B) as key material.
3. The ZSK signs the non-DNSKEY RRsets of the zone.

An adversary who breaks algorithm B can forge signatures that validate
against a currently published ZSK, but cannot substitute a ZSK of their
own choosing without forging an algorithm-A signature on the apex
DNSKEY RRset. The adversary's forgery window is therefore bounded by
the lifetime of any individual ZSK. This bound is what compensates for
algorithm B being weaker than algorithm A.

Without a normative bound on ZSK lifetime, this argument has no force:
a long-lived ZSK gives a future adversary an unbounded opportunity to
exploit a cryptanalytic advance against algorithm B. The completeness
rule of {{!RFC4035}} did not by itself prevent this scenario either --
{{!RFC6840}} Section 5.11 permits a validator to validate using any
single supported algorithm -- but it did make an algorithm-A
signature available on every RRset, so a validator that supported A
*could* choose to require it. The algorithm-split profile of
{{p-algsep}} removes that option: under the profile, non-DNSKEY
RRsets carry only algorithm-B signatures, and no validator can fall
back to A. An explicit cadence bound on B must take its place.

## The Requirement

A zone signed under the algorithm-split profile of {{p-algsep}} MUST
roll its ZSK at a cadence T appropriate to the current threat estimate
against algorithm B. T is intentionally not a fixed value in this
document, because the appropriate value depends on cryptanalytic
progress and on the deployment of cryptographically relevant quantum
computers (CRQCs), neither of which can be predicted at the time of
writing.

The appropriate value of T is a matter of operator security policy. It
is informed by external threat tracking -- for example, the
post-quantum cryptanalysis guidance of the IETF (notably the Crypto
Forum Research Group) and of national bodies such as NIST's
post-quantum cryptography project -- rather than fixed by this
document. Operationally, T is expressed as the ZSK effectivity period
and realized using the established key-rollover machinery of
{{?RFC6781}} and the rollover-timing parameters of {{?RFC7583}}; what
the algorithm-split profile adds is only that this period is now a
security parameter compensating for the strength asymmetry between
algorithms A and B, not merely an operational-convenience interval as
in {{?RFC6781}}.

As an initial guideline, operators of algorithm-split zones SHOULD
begin with T no greater than one month, and SHOULD be prepared to
reduce T to one week or less as threat estimates against algorithm B
sharpen. Operators SHOULD treat T as a tunable policy parameter rather
than a static configuration value.

Signing implementations (including BIND, Knot, Cascade, and others)
are expected to encode per-algorithm minimum cadences as
policy and to refuse to operate a zone under the algorithm-split
profile with a ZSK lifetime exceeding those minima. Such policies are
out of scope for this document, which only requires that *some*
appropriate cadence be enforced.

## The Parent's Signature on the Child DS Is Part of the Argument

The chain-of-trust argument in {{p-zskcadence}} assumes that the
parent's DS RRset is authentic. That authenticity rests on the key
with which the parent signs the child's DS RRset -- typically the
parent's ZSK, though a parent operating with a CSK signs with that key
instead. If an adversary can forge that signature, the adversary can
substitute the child's DS, and thereby the child's KSK; the child's
algorithm-A protection then provides no benefit.

This is a general property of DNSSEC: a zone is no more trustworthy
than the weakest link between it and the trust anchor. The relevant
property of the parent is therefore the strength of the key signing
the child DS RRset against the threat -- a function of both that
key's algorithm and the cadence at which the parent rolls it. A
parent that signs with a strong algorithm needs to roll only at the
normal operational cadence; a parent that signs with a weaker
algorithm needs to roll faster, to bound the window in which a future
cryptanalytic break against that algorithm could be exploited.
Either way, the obligation is on the parent's own configuration,
independent of whether any particular child uses the algorithm-split
profile. {{s-root}} discusses the special case of
the root zone.

# Part 3: DS Algorithm Number as a Size Signal for the DNSKEY RRset {#p-dssignal}

## The Truncation Round Trip

When a resolver validates a delegation, it retrieves the child's DNSKEY
RRset. If the KSK uses a large algorithm, the DNSKEY RRset together
with its RRSIG commonly exceeds the EDNS(0) UDP response size that has
become a de facto ceiling in much of the deployed base (frequently 1232
octets). A UDP query for such a DNSKEY RRset returns a truncated
response with the TC bit set, and the resolver must repeat the query
over a connection-oriented transport. This costs an extra round trip
and a handshake on the first validation of the zone.

## Resolver Behavior

A resolver that has obtained a child's DS RRset MAY use the algorithm
number(s) in that DS RRset to decide how to query the child DNSKEY
RRset. If the resolver recognizes a DS algorithm as one whose keys and
signatures are large enough that the DNSKEY RRset is likely to exceed
its UDP response-size limit, the resolver SHOULD query the DNSKEY RRset
directly over a transport it expects to handle a large response,
rather than first attempting UDP and incurring a truncated response.

This document deliberately does not name a specific transport. A
resolver may use TCP, DNS-over-TLS, DNS-over-QUIC, or any other
transport it considers suitable for large responses. The choice of
transport is a local matter and is expected to evolve as the transport
landscape evolves; this document defines the *signal* but not the
response to it.

This is a local optimization. It changes neither the wire format nor
the validation outcome. A resolver that does not implement it simply
experiences the existing UDP-then-fallback behavior.

## Identifying Large Algorithms

To apply this signal a resolver needs to map an algorithm number to the
property "the DNSKEY RRset is likely too large for UDP."

A compiled-in default set of algorithm numbers that are classified as
"large" is a reasonable starting point, and resolver implementations
are expected to ship such a default reflecting the algorithms known at
the time of release.

A compiled-in default is not sufficient on its own. Until the set of
post-quantum DNSSEC algorithms in operational use has stabilized -- a
process that will include experimentation, including through the
experimental algorithm range suggested by
{{?I-D.johani-dnsop-dnssec-alg-experimental-range}} -- resolver
implementations SHOULD provide a configuration mechanism that allows
the operator to override the compiled-in classification.

## Limitations

The DS algorithm number reflects the KSK algorithm only. The signal is
reliable when the KSK is the large component of the DNSKEY RRset, which
is exactly the deployment of {{p-algsep}}. If a zone instead paired a
small KSK algorithm with a large ZSK algorithm, the DNSKEY RRset could
still be large while the DS signaled a small algorithm; the signal would
be a false negative and the resolver would fall back to the existing
UDP-then-fallback behavior. A false positive (treating a small DNSKEY
RRset as large) causes only an unnecessary use of a large-capable
transport and never affects correctness.

# The Root Zone {#s-root}

The root zone is the most exposed zone in DNSSEC: its KSK is a trust
anchor for the entire namespace, and its ZSK signs the DS RRsets of
every TLD. The mechanisms of this document apply to the root zone with
particular force. This section is a worked example: it illustrates how
{{p-algsep}}, {{p-zskcadence}}, and {{p-dssignal}} apply at the root,
and recommends a deployment profile. The normative requirements of
{{p-algsep}} and {{p-zskcadence}} continue to apply; the
recommendations in this section are non-normative, with the
exception of the resolver-transport recommendation in
{{s-root-transport}}, which restates a SHOULD applicable to resolvers
generally.

## Root KSK

The root KSK SHOULD use a post-quantum algorithm with conservative
security properties. Hash-based signature schemes such as those of
{{FIPS205}} are well-suited to this role because their security rests
on the hash function alone, with no algebraic structure to attack.
Concrete instantiations such as SLH-DSA-128s offer small public keys
and very long-lived security at the cost of large signatures -- a
trade-off that is acceptable for a key whose signature appears only on
the apex DNSKEY RRset.

## Root ZSK

The root ZSK SHOULD also use a post-quantum algorithm, but one with
smaller signatures than the root KSK algorithm. The algorithm-split
profile of {{p-algsep}} does not require the ZSK algorithm to be
classical; it requires only that it differ from the KSK algorithm.
Selecting a post-quantum ZSK algorithm with comparatively smaller
signatures (examples in the current literature include some
multivariate constructions, with MAYO as one candidate among others)
keeps DS responses and other root-zone responses within a manageable
size envelope while still providing post-quantum integrity for root
zone data.

Naming a specific algorithm is out of scope for this document; the
recommendation is that the root ZSK algorithm be (a) post-quantum and
(b) substantially smaller in signature size than the root KSK
algorithm.

## Root ZSK Rotation Cadence

The root zone has on the order of a thousand delegations and a small,
well-resourced operational team; its ZSK rotation cadence is not
limited by signing throughput. Given the root's role as the apex of
every DNSSEC trust chain, and the cross-dependency discussed in
{{p-zskcadence}}, the strength of the key signing DS RRsets in the
root zone is a security parameter of every zone in the tree. That
strength is the combination of the algorithm used and the cadence at
which the key is rolled. The root zone operators have historically
chosen and managed the root ZSK with this combined strength in mind,
and are expected to continue doing so as threat estimates evolve.

## Transport for Root Queries {#s-root-transport}

The root zone is a special case for the DS-based size signal of
{{p-dssignal}}: by construction it has no parent, so no DS RRset
exists from which a resolver could learn that the root's KSK uses an
algorithm with large signatures. The size-signal logic of
{{p-dssignal}} therefore does not apply to root queries.

This document takes a forward-looking position: well in advance of
any rollover of the root zone to a PQ-safe algorithm with large
signatures, resolvers SHOULD adopt a transport suitable for large
responses (TCP, DoT, DoQ, or another) for all queries to the root
zone, rather than UDP/53. Resolvers make relatively few distinct
queries to the root zone in steady state, so the per-query cost of
doing this for all root queries is small in aggregate, and the
transition to a large-signature root then becomes operationally
invisible to resolvers that have already moved their root traffic
off UDP/53. A coordinated truncation event affecting the entire
resolver population at the moment of a root rollover to a
large-signature algorithm is thereby avoided.

A consequence of the preceding paragraph is that the size constraints
on the root zone are largely a question of cache and bandwidth, not of
UDP truncation. The root MAY therefore use larger DS-RRset signatures
than would be acceptable for a zone served predominantly over UDP.

# Operational Considerations

The large DNSKEY RRset of an algorithm-split zone is retrieved and
validated once per DNSKEY-TTL per resolver and then cached; subsequent
queries for ordinary zone data return small, ZSK-signed responses
that fit comfortably in UDP. The large object is thus a
once-per-TTL-per-cache cost, which {{p-dssignal}} further reduces by
avoiding the truncated-UDP round trip.

Rolling a large KSK transiently enlarges the DNSKEY RRset further, as
it must hold both the outgoing and incoming KSKs during the rollover.
Operators should account for this when sizing transport expectations.

A validator that does not support the KSK algorithm cannot follow the
DS-based chain of trust and treats the delegation as Insecure, exactly
as for any rollout of a new algorithm. Deploying a large or
post-quantum KSK therefore has the same backward-compatibility profile
as introducing any new DNSSEC algorithm.

The ZSK rotation cadence required by {{p-zskcadence}} interacts with
cache TTLs, key-management automation, and HSM throughput. Operators
adopting the algorithm-split profile SHOULD verify that their
operational pipeline can sustain the required cadence before deploying
the profile.

# Security Considerations {#security}

## Why the Completeness Relaxation Is Safe

The DNSSEC algorithm-completeness rule of {{!RFC4035}} Section 2.2
and {{!RFC6840}} Section 5.11 exists to prevent algorithm-downgrade
attacks in deployments where multiple algorithms play *peer* roles:
each algorithm is independently capable of authenticating zone data,
and an attacker who breaks the weaker of two peers can forge data
and strip signatures from the stronger one. Completeness ensures
that every RRset is independently protected under every algorithm a
validator might choose, and operator policy can require validation
under the strongest available algorithm.

In the algorithm-split profile of {{p-algsep}}, the KSK-side and
ZSK-side algorithms are *not* peers. They occupy distinct,
structurally asymmetric roles in a fixed chain of trust, derived in
{{p-zskcadence}}: an adversary who breaks the ZSK algorithm cannot
substitute a ZSK of their own choosing without also forging a
KSK-algorithm signature on the apex DNSKEY RRset. The peer-role
attack that completeness was designed to prevent does not apply,
because the algorithms are not peers.

This eliminates peer-substitution downgrade outright. It does not,
however, preserve the residual forgery-window bound that completeness
afforded even outside the peer-role case; the relaxation trades that
absolute guarantee (a forgery under the weaker algorithm cannot
validate at all) for a time-bounded one (such a forgery validates only
within a single ZSK's lifetime). The next paragraph describes that
residual guarantee, and {{p-zskcadence}} restores it by other means.
The safety claim of this document is therefore a claim about the
combination, not about the relaxation in isolation.

What completeness *did* provide, even outside the peer-role case,
was an unforgeable upper bound on the lifetime of an attacker's
forgery window: a non-DNSKEY RRset signed under both algorithms
gave an A-supporting validator the option to require an A signature
and thereby refuse any B-only forgery. The algorithm-split profile
removes that fallback. The cadence requirement of {{p-zskcadence}}
takes its place: instead of being prevented by signature redundancy,
the forgery window is bounded by ZSK lifetime.

The safety argument for this document is therefore *structural
asymmetry plus bounded ZSK lifetime*. This is why {{p-algsep}} and
{{p-zskcadence}} are inseparable.

## Threat Model for the Transition

In the most-discussed near-term transition, algorithm A is
post-quantum (or otherwise expected to be long-lived) and algorithm
B is a traditional algorithm such as ECDSA or Ed25519. The
remainder of this section uses that instance as the worked example;
the analysis carries over to the more general case where algorithm
B is post-quantum but with a shorter security margin than algorithm
A. The most relevant threat in the near-term case is the future
arrival of a cryptographically relevant quantum computer capable of
breaking algorithm B. Under that threat:

* Long-term data integrity guarantees for non-DNSKEY RRsets are not
  provided by this document; an attacker with a CRQC can forge
  ZSK-signed data within the window of a published ZSK's lifetime.
  The {{p-zskcadence}} cadence bounds this window.

* Long-term trust-anchor integrity *is* provided, because the KSK
  algorithm (A) is chosen to resist a CRQC. A validator with a stable
  algorithm-A trust anchor retains the ability to detect substituted
  KSKs across time.

* The combination is therefore appropriate as a transition strategy:
  it exercises large-key handling, transport, and operational tooling,
  and protects the longest-lived element (the trust anchor), while
  acknowledging that bulk-zone integrity against a CRQC requires
  algorithm B to also be post-quantum (as discussed for the root in
  {{s-root}}).

## Cross-Zone Dependency

{{p-zskcadence}} establishes that a child zone in the algorithm-split
profile is no more secure than the parent's signature on its DS
RRset. This is a general DNSSEC property and not a novel weakness,
but the algorithm-split profile makes it operationally visible: a
child KSK that uses a strong post-quantum algorithm can give the
misleading impression that the child is post-quantum-secure
end-to-end, when in fact the parent's DS-signing key -- typically a
classical ZSK -- remains the binding strength of the chain until the
parent itself transitions.

The operational implication: a parent whose children adopt the
algorithm-split profile SHOULD treat the strength of its DS-signing
key (algorithm and rotation cadence together) as a security
parameter of those children, not solely of itself.

## Transport Signal

The DS-based size signal of {{p-dssignal}} is a transport optimization
with no effect on validation. A misjudgment about an algorithm's size
results only in an unnecessary use of a large-capable transport, or in
a fallback to the existing UDP-then-fallback behavior; it cannot affect
whether data validates.

# IANA Considerations {#iana}

This document requires no IANA action. {{p-algsep}} and
{{p-zskcadence}} update the signing and validation rules of
{{!RFC4035}} and {{!RFC6840}}, and {{p-dssignal}} is a resolver-side
local optimization.

--- back

# Acknowledgments
{:numbered="false"}

The author acknowledges that Ondřej Surý arrived independently at the
idea of splitting the KSK and ZSK algorithms, and thanks him for
substantive discussions on this topic during RIPE 92.

The author also thanks Joe Abley (Cloudflare), Christian Elmerot
(Cloudflare), Peter Thomassen (deSEC), and Erik Bergström (Swedish
Internet Foundation) for valuable insights and suggestions.
