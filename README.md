# Lombard deterministic deposit addresses

This module defines a method for deriving deterministic Lombard deposit
addresses based on the depositor's destination chain type, chain id, and
destination wallet address. This makes it possible to have many depositors
send funds to addresses controlled by a single CubeSigner key, meaning that
policies only need to be set once and for all on that key. It also means
that users and third parties (e.g., custodians) can independently compute
their deposit address as a check against phishing.

In particular, this document:

- defines a method for tweaking secp256k1 ecdsa public keys that is analogous
  to the one used for Taproot keys, and

- defines methods for deriving the tweak value from a Lombard depositor's
  chain type, chain id, and destination wallet address.

The rest of this README defines the tweak and derivation methods.

Notation: this document uses `||` to indicate concatenation.

## Tweaking secp256k1 ECDSA keys

The basic idea is to first, derive a secp256k1 scalar (i.e., an integer less
than the order of the secp256k1 curve) from an arbitrary 32-byte array; then
to use this scalar to additively tweak the key. In other words,

    tweaked_pk = untweaked_pk + tweak_scalar * G

where `G` is the canonical generator (a.k.a. "base point") of secp256k1. This
is the same tweaking method used by BIP32, and is related to the one used for
Taproot tweaking.

### Computing a tweak scalar

The input to this procedure is a secp256k1 public key and 32 tweak bytes.
Note that the tweak byte array *MUST* be exactly 32 bytes. Variable-length
arrays are disallowed for security reasons.

The tweaking procedure is defined as follows:

```
def tweakScalar(pubkey, tweakBytes):
    if len(tweakBytes) != 32:
        panic("tweak must be exactly 32 bytes")

    tag = sha256("SegwitTweak")             # the hash input is 11 ASCII bytes
    pkBytes = pubkey.serializeCompressed()  # 33-byte compressed SEC1 format

    # hash the concatenation `tag || tag || pkBytes || tweakBytes`
    # NOTE: `tag` is intentionally hashed twice, following BIP340
    tweakHash = sha256(tag, tag, pkBytes, tweakBytes)

    # interpret this scalar as a big-endian integer.
    #
    # if this value is greater than the order of the secp256k1 curve,
    # this conversion MUST fail. Note, however, that this happens with
    # negligible probability, so it is fine to simply panic in this case
    # because it will never happen in practice
    return ScalarFromBigEndianBytes(tweakHash)
```

### Computing a tweaked public key

This procedure tweaks a public key using the tweak scalar defined above.

```
def tweakPublicKey(pubkey, tweakBytes):
    tScalar = tweakScalar(pubkey, tweakBytes)

    # the tweak point is computed as tweakScalar * G
    tweakPoint = tScalar * Secp256k1BasePoint

    # tweaked public key is obtained by adding tweakPoint to public key
    return pubkey + tweakPoint
```

### Computing a tweaked secret key

This procedure tweaks a secret key using the tweak scalar defined above.

```
def tweakSecretKey(seckey, tweakBytes):
    # compute the tweak scalar
    pubkey = seckey.publicKey()
    tScalar = tweakScalar(pubkey, tweakBytes)

    # the tweaked secret key is just the sum of the tweak scalar and the secret key
    #
    # this matches the public key procedure:
    #    pubkey = seckey * G
    #    tweaked_pubkey = pubkey + tweak_scalar * G
    #                   = seckey * G + tweak_scalar * G
    #                   = (seckey + tweak_scalar) * G
    return seckey + tScalar
```

## Computing tweak bytes for Lombard deposits

This section defines the procedure for computing the `tweakBytes` value used
in the tweaking procedure, based on the Lombard depositor's information.

The method defined here uses a tagged hash similar to the one defined in BIP340.
The tag for this hash is `sha256("LombardDepositAddr")`.

The input to the tagged hash comprises two values, `auxData` and `chainData`.
`auxData` is a 32-byte field whose format is common across all chain types.
This field can be used to encode, for example, referrer-ids.

The `chainData` value's format depends on the chain type. To differentiate
among chain types, all `chainData` values are tagged with a chain-specific
byte. As new chain types are added to Lombard, this definition will be
extended. Every chain type's `chainData` value MUST start with a unique byte;
this prevents any ambiguity among `chainData` values for different chains,
which would be bad because it could result in a case where a single deposit
address corresponds to two different user intents (i.e., deposit on chain1
vs deposit on chain2).

The `chainData` format for a new chain type MUST meet the following criteria:

- it must begin with a chain-type byte that is unique to this chain type;

- it must include identifying information for the chain, the destination
  bridge address, and the depositor's destination wallet address; and

- it must be injectively encoded, i.e., each field must either be fixed length
  or must unambiguously encode its length.

The following procedure computes tweak bytes from `auxData` and `chainData`:

```
def lombardTweakBytes(auxData, chainData):
    tag = sha256("LombardDepositAddr")      # the hash input is 18 ASCII bytes

    # hash the concatenation `tag || tag || auxData || chainData`
    # NOTE: `tag` is intentionally hashed twice, following BIP340
    return sha256(tag, tag, auxData, chainData)
```

### EVM chains

The chain-type byte for EVM chains is `0x00`.

The `chainData` for EVM is

    0x00 || chain_id || lbtc_contract_addr || destination_wallet_addr

where

- `chain_id` is a 32-byte big-endian encoding of the chain-id

- `lbtc_contract_addr` is the LBTC contract address on the destination EVM chain

- `destination_wallet_addr` is the depositor's 20-byte EVM address

## Security considerations

The additive tweaking approach described in this document is secure when
the SHA256 compression function is modeled as a fixed-length random oracle.
In addition, distinct deposits (i.e., distinct chains, recipient addresses,
`auxData`, etc.) will result in distinct deposit addresses. We now justify
these claims.

To start, notice that the method by which `tweakHash` is computed from
`auxData` and `chainData` is closely related to NMAC and HMAC (see [BCK05],
[CDMP07]).  In particular, the functions `lombardTweakBytes` and `tweakScalar`
use distinct 32-byte `tag` values, and each function injects its value into
SHA-256 twice. Since SHA-256's block length is 64 bytes, we have that each
function hashes a distinct block; equivalently, each function uses SHA-256
with distinct IV. Further, the output of `lombardTweakBytes` is hashed
(along with a domain separator, namely, the compressed SEC1 serialization
of the public key) in `tweakScalar`. In short, the composition of these
two functions is `Hash(IV2, pk || Hash(IV1, data)`. [CDMP07] prove that
constructions of this form are indifferentiable from a random oracle when
`Hash`'s compression function is modeled as a random oracle.

Finally, Groth and Shoup [GS22] show that the additive tweaking method used
in this document maintains the unforgeability of ECDSA when the tweak value
is derived from a random oracle.

Beyond unforgeability, we also require that distinct deposits use distinct
deposit addresses. This property clearly holds as long as the construction
is collision resistant, i.e., as long as it is infeasible to find distinct
inputs to `lombardTweakBytes` that result in the same tweak. Because
SHA-256 is collision resistant, and because `auxData` has a fixed length
of exactly 32 bytes, it suffices to show that the `chainData` encoding
is injective, since this guarantees that every valid input to the hash
function in `lombardTweakBytes` corresponds to exactly one input.

The EVM `chainData` encoding is injective because it is a concatenation
of fixed-length fields. For new chain types, the requirements described
above (i.e., `chainData` starts with a distinct chain-type byte and contains
only fixed-length or length-prefixed fields) guarantee injectivity.

[BCK05]: <https://cseweb.ucsd.edu/~mihir/papers/cascade.pdf>
[CDMP07]: <https://cs.nyu.edu/~dodis/ps/merkle.pdf>
[GS22]: <https://eprint.iacr.org/2021/1330.pdf>

## License

The code in this directory is

Copyright (C) 2024 Cubist, Inc.

See the [NOTICE] file for licensing information.

[NOTICE]: <NOTICE>
