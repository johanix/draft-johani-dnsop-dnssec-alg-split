# Analysis: Should the completeness relaxation be gated on the KSK algorithm?

Status: design analysis / discussion note (not part of the I-D)
Context: draft-johani-dnsop-dnssec-alg-split-00
Question: Is there a realistic compromise in which a validator accepts the
algorithm split, but only for certain KSK algorithms (typically identified
via the DS algorithm number)? Or does such logic become too difficult to
maintain and ensure?

## The two possible designs

**A. Unconditional (what the draft specifies today).** The relaxation applies
whenever the parent DS and apex DNSKEY match the structural profile of
{{p-algsep}} -- K and Z disjoint, the apex DNSKEY carries at least one key of
each algorithm in K and Z, non-DNSKEY RRsets signed by every algorithm in Z,
etc. The validator does not care *which* algorithms are in K.

**B. Gated.** The relaxation applies only when the KSK algorithm (read from the
DS) is on an approved "this algorithm is allowed to be split-only" list. A
split with, e.g., an ECDSA KSK and an Ed25519 ZSK would *not* receive the
relaxation and would be marked Bogus as before.

## Assessment

Gating is technically easy, but the gate buys little -- and it imports a
maintenance problem into a *security-critical* path.

### 1. The gate would be mechanically trivial to implement

Part 3 already requires an algorithm-number -> property table (the "is this
DNSKEY likely large?" classifier). Reusing it to also mean "is this algorithm
eligible to be a split KSK?" is a few lines. Feasibility is not the obstacle.

### 2. The security argument does not depend on the KSK being large or PQ

This is the crux. What makes the split safe is *structural asymmetry +
bounded ZSK lifetime*. Neither leg references the KSK algorithm's identity:

* The asymmetry comes from K and Z occupying different chain positions and
  being **disjoint** -- not from K being "big."
* The forgery-window bound comes from **ZSK cadence** -- a property of Z, not K.

So a gate keyed on the *KSK* algorithm gates on the wrong variable. The
property that actually has to hold for safety ("Z is rolled fast enough for
its threat level") is **not visible in the DS at all** and is not an
algorithm-identity question. The draft deliberately defines the profile
"entirely in terms of the contents of the parent DS RRset and the apex DNSKEY
RRset" *structurally*; an algorithm-identity gate would break that clean
framing without closing a real gap.

### 3. What would a gate actually prevent? Mostly footguns, not attacks

The realistic thing gating stops is an operator doing a split with two
*classical* algorithms (ECDSA KSK / Ed25519 ZSK) -- using the relaxation when
there is no size motivation and arguably no PQ-transition justification. That
is a *policy* concern (do not relax completeness gratuitously), not a
*downgrade* concern. It is also weakly self-limiting: with two small
algorithms there is no size payoff, so the incentive to do it is low.

If the worry is the genuinely dangerous case -- **strong-KSK / weak-ZSK
lulling people into thinking the zone is PQ-secure end-to-end** -- gating the
validator does not help, because that case *passes* any sane gate (the KSK is
exactly the strong/PQ algorithm one would allow-list). The gate admits
precisely the configuration whose residual weakness is the real concern.

### 4. The maintenance / centralization cost is real and lands in the worst place

A validator-side allow-list of "splittable KSK algorithms" has the classic
problems, and they are worse here than for Part 3:

* **It becomes correctness-critical, not an optimization.** Part 3's table, if
  wrong, costs a round trip. A *gating* table, if wrong, marks a
  legitimately-signed zone **Bogus** (resolution failure) or fails open,
  depending on the default. Both are bad; the asymmetry between "slow" and
  "Bogus" is exactly why algorithm-identity logic should stay off the
  validation path.
* **New algorithms stall behind resolver updates.** Every new PQ algorithm
  (and there will be a stream of them, plus the experimental range proposed by
  the companion draft) could not be used as a split KSK until enough
  validators ship an updated list -- a deployment-coupling tax on exactly the
  transition this draft is trying to smooth.
* **Default behavior is a no-win.** Unknown KSK algorithm -> if you *deny* the
  split, you break forward compatibility; if you *allow* it, the gate is not
  really gating. The structural approach sidesteps this dilemma entirely.

## The narrow case where gating would be defensible

One version is worth entertaining: a **policy knob, off by default,
validator-local** -- "refuse the completeness relaxation unless the KSK
algorithm is in *my* configured set." This is defensible because:

* It is the operator's own risk policy, not a protocol requirement, so there
  is no central registry and no interop coupling.
* It fails in the *operator's* direction (they chose to be strict), like an
  algorithm denylist today.
* It parallels how the draft already handles Part 3's classifier --
  compiled-in default, operator override.

Note this is **subtractive local policy**, not a change to the protocol's
acceptance rule. It does not make the *spec* gated; it lets a cautious
validator be stricter than the spec. That is always allowed and probably
worth a one-line mention in the validator-side section or Security
Considerations.

## Bottom line

* A **protocol-level** gate keyed on the DS/KSK algorithm: advise **against**
  it. It gates on the variable that is *not* load-bearing (KSK identity) while
  the variable that *is* (ZSK cadence) stays invisible; it admits the one
  genuinely worrying config; and it relocates an algorithm-number table from a
  cost-only path to a correctness-critical one, with a registry /
  deployment-coupling burden that fights the draft's whole purpose.
* A **validator-local, opt-in strictness policy**: reasonable and cheap,
  because it is additive caution rather than a protocol rule -- and it inherits
  the "compiled-in default + override" pattern Part 3 already establishes.

The structural definition the draft already uses is the right call. The
compromise worth offering is not "gate the protocol," it is "explicitly permit
a validator to be locally stricter."
