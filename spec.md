# x402-doge — the `exact` scheme on Dogecoin

**Status:** Draft
**Version:** 0.1.0
**Chain:** Dogecoin (Dogecoin Core 1.14.x relay policy)
**x402 version:** 2
**Scheme:** `exact`
**Networks:** `bip122:1a91e3dace36e2be3bf030a65679fe82` (mainnet), `bip122:bb0a78264637406b6360aad926284d54` (testnet)
**Reference verifier:** [`verify.mjs`](./verify.mjs) (Node 18+, no dependencies)

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are used as described in RFC 2119.

---

## 1. Summary

x402 lets an HTTP server answer `402 Payment Required` with machine-readable payment terms. The client pays and retries, and a facilitator checks and settles the payment. This document defines how the x402 v2 `exact` scheme works when the network is Dogecoin and the asset is DOGE.

The client builds a normal Dogecoin transaction that pays exactly `amount` koinu to `payTo`. It carries one `OP_RETURN` output that binds it to the server's per-request `nonce`. The client signs it with its wallet (Dojak, MyDoge, or any wallet that signs PSBTs or raw transactions) and sends the signed raw transaction in the `PAYMENT-SIGNATURE` header. The facilitator checks it against Dogecoin Core and broadcasts it. The resource is served on mempool acceptance (0-conf) or after `minConfirmations`.

Nothing in this document changes Dogecoin consensus, relay policy, or any inscription or ÐLand/ÐMaps indexer rule. A payment is an ordinary standard transaction.

## 2. Scheme and network modeling

x402 separates the **scheme**, which is how value moves, from the **network**, which is where it moves.

- `scheme` MUST be `"exact"`. The client pays a known amount, and Dogecoin has nothing that maps onto `upto`-style allowances. The family is new, so this document does not register a new scheme name; it adds a network to `exact`, the same way Cardano, Stellar and others did.
- `network` MUST be a CAIP-2 identifier in the `bip122` namespace: the first 32 hex characters (16 bytes) of the genesis block hash, as registered at namespaces.chainagnostic.org:

| Network | CAIP-2 | Genesis hash prefix | P2PKH / P2SH version bytes |
| --- | --- | --- | --- |
| Dogecoin mainnet | `bip122:1a91e3dace36e2be3bf030a65679fe82` | `1a91e3dace36e2be3bf030a65679fe82…` | 30 (`D…`) / 22 (`9…`, `A…`) |
| Dogecoin testnet | `bip122:bb0a78264637406b6360aad926284d54` | `bb0a78264637406b6360aad926284d54…` | 113 (`n…`) / 196 (`2…`) |

  Regtest has no CAIP-2 registration. Implementations MAY accept `bip122:regtest-dogecoin` for local testing and MUST NOT advertise it in `GET /supported` on a public facilitator.
- `asset` MUST be `"DOGE"`. This follows the `lnbtc` precedent of naming the native coin, because DOGE has no contract address. Tokens (DRC-20, Doginals, Dunes) are out of scope (§15).
- `amount` MUST be a base-10 integer string in **koinu** (1 DOGE = 100,000,000 koinu), with no sign, no leading zeros, and no decimal point. `amount` MUST be at least `1000000` (0.01 DOGE, the soft dust limit, §10) and at most `1000000000000000000` (MAX_MONEY).

## 3. Transfer family declarations

The x402 `exact` scheme has two families. This network uses the **facilitator-submitted** family: the facilitator broadcasts. The x402 spec requires such networks to declare four things.

| Declaration | Dogecoin |
| --- | --- |
| `assetTransferMethod` | `"rawTransaction"`. The payload is a fully signed transaction. |
| Fee payer | **The payer.** The fee is the input total minus the output total, inside the signed transaction. The facilitator never adds inputs and never pays fees. |
| Replay primitive | **The spent outpoints.** A UTXO can be spent once, so the transaction can confirm at most once. Request-level replay is stopped by the `nonce` binding (§6) and the facilitator's dedup store (§9.3). |
| Validity window | The network has none: a signed transaction with `nLockTime = 0` is valid until one of its inputs is spent. The window is set by `extra.validBefore` and enforced by the facilitator (§8). After it, the payer cancels by spending any input elsewhere. |
| Duplicate submission | The facilitator MUST dedup on the `nonce` **and** on every spent outpoint, and SHOULD also dedup on the txid (§9.3). A second `/settle` for the same nonce returns the stored result or `duplicate_settlement`. |

A client-submitted variant is possible, where the client broadcasts and sends the txid. It is **not** defined here. It gives a server a txid it cannot tie to the request before it confirms, and it moves 0-conf risk to the server with less information.

## 4. `PaymentRequirements`

Each `accepts[]` entry in a `PaymentRequired` response has the standard v2 fields:

| Field | Type | Rule |
| --- | --- | --- |
| `scheme` | string | `"exact"` |
| `network` | string | a CAIP-2 id from §2 |
| `amount` | string | koinu, see §2 |
| `asset` | string | `"DOGE"` |
| `payTo` | string | a Base58Check P2PKH or P2SH address for `network` |
| `maxTimeoutSeconds` | number | the longest the resource server will wait for settlement. SHOULD be at least `60 × (minConfirmations + 2)` when `minConfirmations > 0`. |
| `extra` | object | REQUIRED for this network, see below |

`extra` fields:

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `assetTransferMethod` | string | yes | `"rawTransaction"` (the x402 reserved key) |
| `nonce` | string | yes | 32 lowercase hex characters (16 bytes), unique per issued requirement. Bound into the transaction (§6). |
| `validBefore` | string | yes | unix seconds, as a decimal string. The facilitator MUST refuse to verify or settle after this time (§8). |
| `minConfirmations` | number | no | an integer from 0 to 60. Default `0`. With `≥ 1`, `paymentFlow` MUST be `"upfront"` (§7). |
| `minFeePerKb` | string | no | the koinu-per-1000-bytes fee floor. Default `"1000000"` (0.01 DOGE/kB). MUST be at least `"100000"` (the 1.14 relay minimum). |
| `paymentFlow` | string | no | the x402 reserved key: `"authorization"` (default, may be omitted) or `"upfront"`. `"escrow"` is not supported. |

Unknown `extra` keys MUST be ignored by clients and MUST be preserved byte-for-byte when the client echoes `accepted`.

A server SHOULD offer the same resource on more than one network or scheme by listing several `accepts[]` entries. For example, `exact` on Base USDC beside `exact` on Dogecoin. Each Dogecoin entry MUST have its own `nonce`.

### 4.1 Nonce issuance (non-normative)

Servers do not need to store issued nonces. A stateless construction is `nonce = HMAC-SHA256(serverKey, resource.url ‖ amount ‖ payTo ‖ validBefore ‖ random16)[0..16]`, with `random16` kept server-side only via the dedup store at settle time. Any construction is fine if two live requirements never share a nonce.

## 5. `PaymentPayload`

```json
{
  "x402Version": 2,
  "resource": { "url": "https://api.example.com/v1/bulk-export" },
  "accepted": { "...the chosen PaymentRequirements, echoed unchanged..." },
  "payload": { "transaction": "<lowercase hex of the signed raw transaction>" }
}
```

- `accepted` MUST be a deep-equal copy of one entry the server issued. The facilitator compares it with the `paymentRequirements` it was given, using canonical JSON (keys sorted, no whitespace). Any difference is `invalid_exact_dogecoin_requirements_mismatch`.
- `payload.transaction` MUST be the lowercase hex of a fully signed, legacy-serialized Dogecoin transaction (Dogecoin has no segwit). It MUST NOT be a PSBT. Clients finalize before sending.
- `payload` MUST NOT contain other keys. Facilitators MUST ignore any that appear.

The whole object travels base64-encoded in the `PAYMENT-SIGNATURE` request header, as in every x402 v2 transport.

## 6. Request binding (`OP_RETURN`)

The transaction MUST contain **exactly one** `OP_RETURN` output. It MUST have value `0` and script:

```
6a 15 78343032 01 <nonce: 16 bytes>
│  │  │        │
│  │  │        └─ binding version 0x01
│  │  └─ ASCII "x402"
│  └─ push 21 bytes
└─ OP_RETURN
```

This is 23 bytes of script and 21 bytes of data, well under the 80-byte data limit of 1.14 (`MAX_OP_RETURN_RELAY = 83`). Core relays only one `OP_RETURN` per transaction, so a payment cannot also carry another protocol's `OP_RETURN`. That is intended: x402 payments do not double as inscriptions or protocol messages.

The binding ties the signed transaction to one issued requirement. Without it, a server cannot tell a payment for this request from any other transfer of the same size to the same address, and the same transaction could be presented to two requests.

## 7. Payment flows and confirmation policy

| `minConfirmations` | `paymentFlow` | Sequence |
| --- | --- | --- |
| `0` (default) | `authorization` (default) | verify → serve the resource → settle (broadcast) → `PAYMENT-RESPONSE`. If the resource handler fails, the server MUST NOT settle, the transaction is never broadcast, and the payer keeps their coins (§11). |
| `0` | `upfront` | verify → settle (broadcast) → serve the resource. Use this when the response cannot be withheld after it starts, such as streams. |
| `≥ 1` | `upfront` (REQUIRED) | verify → settle (broadcast, then wait for depth) → serve the resource. While the depth is not reached, `/settle` returns `success: false, errorReason: "settlement_pending"` with the txid (§9.2). |

`authorization` with `minConfirmations ≥ 1` is invalid: the server would serve before it had any assurance. Facilitators MUST reject that as `invalid_payment_requirements`.

### 7.1 Recommended tiers (non-normative)

Dogecoin targets one block a minute. These are starting points, not rules, and each operator sets its own risk tolerance.

| Amount | Suggested `minConfirmations` | Rationale |
| --- | --- | --- |
| < 25 DOGE | 0 | Low value, with the RBF and input-confirmation rules of §8 making a double-spend costly relative to the gain. |
| 25 – 1,000 DOGE | 1 – 2 | One to two minutes. |
| 1,000 – 100,000 DOGE | 6 | About six minutes. |
| > 100,000 DOGE | 30+ | Treat as a large settlement. Consider not using x402 at all. |

## 8. Verification rules

A facilitator's `POST /verify` MUST apply every rule below, and `POST /settle` MUST re-apply them before broadcasting. Rules are in evaluation order; the first failure decides `invalidReason`. Where a rule cites a Core constant, the value is from Dogecoin Core v1.14.9.

### 8.1 Envelope

1. `x402Version` is `2`, otherwise `invalid_x402_version`.
2. `paymentRequirements.scheme` is `"exact"` (`invalid_scheme`), `network` is supported (`invalid_network`), and `asset` is `"DOGE"` (`invalid_exact_dogecoin_asset_mismatch`).
3. `extra` is well-formed per §4, `amount` is in range, and `payTo` decodes for `network`. Otherwise `invalid_payment_requirements`.
4. `paymentPayload.accepted` equals `paymentRequirements` (canonical JSON), otherwise `invalid_exact_dogecoin_requirements_mismatch`.
5. now ≤ `validBefore` + 30 s skew, otherwise `invalid_exact_dogecoin_expired`.

### 8.2 Static transaction checks (no node needed)

6. `payload.transaction` is lowercase hex and decodes as a legacy transaction with nothing trailing. Varints are canonical. There is at least one input and one output. Otherwise `invalid_exact_dogecoin_transaction_malformed`.
7. The size is at most 100,000 bytes (`MAX_STANDARD_TX_WEIGHT` 400,000 with no witness) and there are at most 100 inputs. Otherwise `invalid_exact_dogecoin_transaction_too_large`.
8. `nVersion` is 1 or 2 (`MAX_STANDARD_VERSION`), otherwise `invalid_exact_dogecoin_nonstandard`.
9. There are no duplicate outpoints (`invalid_exact_dogecoin_transaction_malformed`) and no null prevouts (coinbase).
10. Locktime: when `minConfirmations = 0`, every input's `nSequence` MUST be `0xffffffff` (no RBF signal, which also makes `nLockTime` irrelevant to consensus; clients SHOULD still set it to `0`). When `minConfirmations ≥ 1`, `nSequence < 0xfffffffe` is allowed (RBF signaling is not the risk there), but `nLockTime` MUST be final at the current tip: `0`, or a height ≤ the tip height. Time-based locktimes (≥ 500,000,000) are refused unless all sequences are final. Violations give `invalid_exact_dogecoin_rbf_signaled` or `invalid_exact_dogecoin_locktime`.
11. Binding: exactly one `OP_RETURN` output, of value 0, with script exactly as §6 for `extra.nonce`. A missing one gives `invalid_exact_dogecoin_binding_missing`; any other difference, `invalid_exact_dogecoin_binding_mismatch`.
12. Recipient: exactly one output whose script equals the `scriptPubKey` of `payTo` (`invalid_exact_dogecoin_recipient_mismatch`), with value **equal** to `amount` (`invalid_exact_dogecoin_amount_mismatch`). Overpayment is not accepted. "Exact" is literal, and it keeps accounting and refunds unambiguous.
13. Every other output is P2PKH or P2SH with value ≥ 100,000 koinu (`DEFAULT_HARD_DUST_LIMIT`, 0.001 DOGE). Otherwise `invalid_exact_dogecoin_nonstandard`.
14. Every input's `scriptSig` is exactly `<sig> <pubkey>`, with a minimal push, a DER signature that is strict (BIP66) and low-S, a sighash byte of `0x01` (`SIGHASH_ALL`), and a 33-byte compressed or 65-byte uncompressed public key. Any other sighash gives `invalid_exact_dogecoin_sighash_type`; other shapes give `invalid_exact_dogecoin_unsupported_input`. Version 0.1 supports P2PKH inputs only. This is what Dojak and MyDoge produce. P2SH multisig inputs are left for a later version.

`SIGHASH_ALL` is required because any weaker type lets a third party change outputs or add inputs after signing, and that would break rules 11–13 after verification.

### 8.3 Prevout checks (needs the node)

15. Each prevout is unspent, **including in the mempool**: `gettxout <txid> <n> true` is not null. Otherwise `invalid_exact_dogecoin_input_missing`. A spend the mempool already holds means a conflicting transaction is in flight.
16. Each prevout's `scriptPubKey` is P2PKH, and `HASH160(pubkey)` matches it (`invalid_exact_dogecoin_unsupported_input` / `script_invalid`). The ECDSA signature verifies over the legacy `SIGHASH_ALL` digest (`invalid_exact_dogecoin_script_invalid`).
17. When `minConfirmations = 0`, every prevout has at least 1 confirmation (`invalid_exact_dogecoin_input_unconfirmed`). This bars chains of unconfirmed parents, which can be evicted or replaced underneath the payment. When `minConfirmations ≥ 1` this rule is RECOMMENDED but not required.
18. A coinbase prevout is mature: 240 confirmations on mainnet and testnet post-DigiShield (`COINBASE_MATURITY_2`). Otherwise `invalid_exact_dogecoin_input_immature`.
19. Fee = Σ prevout values − Σ output values. It MUST satisfy:
    - fee ≥ `ceil(size × minFeePerKb / 1000)` + 1,000,000 × (outputs, other than `OP_RETURN`, below 1,000,000 koinu). This is `GetDogecoinDustFee`: each soft-dust output adds 0.01 DOGE to the required fee. Otherwise `invalid_exact_dogecoin_fee_too_low`.
    - fee ≤ 10,000,000,000 koinu (100 DOGE, `DEFAULT_TRANSACTION_MAXFEE`). Otherwise `invalid_exact_dogecoin_fee_too_high`.
    - Σ inputs ≥ Σ outputs, otherwise `insufficient_funds`.
20. Core script check: the facilitator SHOULD call `signrawtransaction <hex> [] []` and require `complete: true` with no `errors`. With no keys supplied, Core only re-runs the existing scripts under the standard verification flags (`STRICTENC`, `DERSIG`, `LOW_S`, `NULLDUMMY`, `CLEANSTACK`, `MINIMALDATA`, …). This is the closest thing to `testmempoolaccept`, which 1.14 lacks. Failure gives `invalid_exact_dogecoin_script_invalid`.

1.14 has no `testmempoolaccept`, so rules 15–20 cannot prove that `sendrawtransaction` will succeed: mempool chain limits and the fee cache can still refuse. Settlement MUST therefore handle a rejected broadcast (§9.2).

`payer` in the `VerifyResponse` SHOULD be the address of the first input's prevout.

## 9. Settlement

### 9.1 Steps

`POST /settle` with the same body as `/verify`:

1. Run §8.1 and §8.2, skipping the expiry check (rule 5) so that a pending settlement can still be polled after `validBefore`. On failure return `success: false`, `errorReason` = the verify reason, `transaction: ""`.
2. **Look up the nonce** in the dedup store (§9.3):
   - claimed by a different txid: `invalid_exact_dogecoin_nonce_used`;
   - same txid, broadcast but not yet at depth: resume at step 6, so polling and retries are idempotent and never rebroadcast;
   - same txid, already settled, or still in flight in another request: `duplicate_settlement`, with `transaction` set to the txid.
3. For a new nonce only: run all of §8, including expiry and the node checks. Then **claim before broadcast**: insert the nonce and every spent outpoint `txid:vout` (insert-if-absent). If an outpoint is already claimed, release what this request claimed and return `invalid_exact_dogecoin_input_claimed`.
4. `sendrawtransaction <hex> false`. `allowhighfees` stays false, so Core enforces its own maximum fee too.
5. Interpret the result:

| Core result | Meaning | Settle response |
| --- | --- | --- |
| returns txid | accepted, or already in the mempool | continue to step 6 |
| error −27 `transaction already in block chain` | already confirmed | continue to step 6 |
| error −26 (rejected), −25 (missing inputs), −22 (decode) | refused | release the claims and return `success: false, errorReason: "invalid_transaction_state"` |
| transport error or unknown | outcome unknown | **keep** the claims and return `success: false, errorReason: "settlement_pending"` with the computed txid |

6. Depth: with `minConfirmations = 0`, return `success: true`. Otherwise read confirmations with `gettxout <txid> <payIndex> true`, falling back to `getrawtransaction <txid> 1` once the merchant has spent the output, which needs `-txindex`. Return `success: true` at depth ≥ `minConfirmations`, and otherwise `settlement_pending`.

The resource server MAY poll `/settle` with the same body until `success: true` or `maxTimeoutSeconds` passes. Each call is idempotent by step 2.

### 9.2 `SettleResponse`

| Field | Value |
| --- | --- |
| `success` | `true` only per step 6 |
| `errorReason` | present when `success` is false |
| `payer` | as in verify |
| `transaction` | the txid in RPC (big-endian) hex. MUST be non-empty for `success: true` and for `settlement_pending`; `""` when nothing was broadcast. |
| `network` | the CAIP-2 network |
| `amount` | `amount` from the requirements (optional in x402, RECOMMENDED here) |

The server sends it base64-encoded in the `PAYMENT-RESPONSE` header.

### 9.3 Dedup store

- Keys: `<network>:nonce:<payTo>:<nonce>` (holding the txid and the state `inflight` / `broadcast` / `settled`) and `<network>:outpoint:<txid>:<vout>`. Implementations MAY add `<network>:txid:<txid>`.
- Each insert MUST be atomic insert-if-absent, and a failed request MUST release the keys it took. A single process can use a map; several facilitator instances MUST share one store with that guarantee (a SQL transaction, Redis `SET NX`, etc.).
- Retention: every key at least until `validBefore` + 1 hour. The reference uses `validBefore` + 24 hours. After that, the signed transaction can still be broadcast by anyone holding it, but the facilitator will not settle it again because rule 5 has expired it.
- Claims on the outpoints, and not only the txid, are REQUIRED. Legacy txids are malleable: a relay node can change an `S` encoding or a push opcode without invalidating the signature, which produces a different txid that spends the same coins. Low-S and strict-DER checks remove the known third-party malleations, but claiming outpoints covers whatever is left.

## 10. Fees and dust (Dogecoin Core 1.14.9)

Values are taken from `src/policy/policy.h`, `src/validation.h`, `src/wallet/wallet.h` and `src/dogecoin-fees.cpp` at tag `v1.14.9`.

| Constant | Value | Effect here |
| --- | --- | --- |
| `RECOMMENDED_MIN_TX_FEE` | 1,000,000 koinu/kB (0.01 DOGE/kB) | The default `minFeePerKb`. Below it, miners following the default policy may not mine the transaction quickly. |
| `DEFAULT_MIN_RELAY_TX_FEE` | 100,000 koinu/kB (0.001 DOGE/kB) | The lowest `minFeePerKb` permitted. |
| `DEFAULT_INCREMENTAL_RELAY_FEE` | 10,000 koinu (0.0001 DOGE) | Only affects RBF replacements, which §8 refuses at 0-conf. |
| `DEFAULT_DUST_LIMIT` (soft) | 1,000,000 koinu (0.01 DOGE) | Each output below it adds 0.01 DOGE to the minimum fee. `amount` must be at least this. |
| `DEFAULT_HARD_DUST_LIMIT` | 100,000 koinu (0.001 DOGE) | An output below it is non-standard and refused. |
| `DEFAULT_TRANSACTION_MAXFEE` | 10,000,000,000 koinu (100 DOGE) | The fee ceiling. Above it Core reports "absurdly-high-fee". |
| `MAX_STANDARD_TX_WEIGHT` | 400,000 (100 kB) | The size ceiling. |
| `MAX_OP_RETURN_RELAY` | 83 bytes of script | The binding uses 23. |

Since 1.14.5, fees are computed on exact size with no rounding up to whole kilobytes. A typical one-input, three-output payment (≈ 226–260 bytes) needs a fee of about 0.0026 DOGE at the default floor. Wallets commonly pay 0.01 DOGE or more, which is fine.

## 11. Failure and refund semantics

- **Not broadcast, not charged.** If verification fails, the resource fails under `authorization`, or settlement is refused, the transaction was never broadcast (or was refused by the network), and the coins never moved. The payer needs no refund. They SHOULD spend one of the inputs back to themselves to cancel the signed transaction for good, because anyone holding it can broadcast it until then. Wallets MAY do this automatically after `validBefore`.
- **Broadcast but resource failed** (`upfront` only, or a server bug). The coins moved, and x402 has no on-chain refund primitive. The server MUST log the txid and nonce and SHOULD refund by sending `amount` minus a network fee to the address of the payer's first input, unless the payer gave a different one out of band. Servers that cannot promise this SHOULD NOT use `upfront`.
- **Pending past `maxTimeoutSeconds`.** The server responds `402` with a fresh `PaymentRequired`, keeps the dedup claims, and treats a later confirmation of the old transaction as a payment received without delivery: it applies the refund rule above, or serves on retry with the same nonce if the resource allows it.
- **Reorg after delivery.** The server accepted the risk when it chose `minConfirmations`. Depth thresholds are the only defense.

## 12. RBF and double-spend

Dogecoin Core 1.14 has BIP125 opt-in replacement enabled by default (`-mempoolreplacement=1`). A transaction can be replaced only if it signals, meaning some input has `nSequence < 0xfffffffe`. Rules 10, 15 and 17 make a 0-conf payment:

- non-replaceable under default relay policy, because no input signals;
- spend only confirmed coins, so no parent can be evicted or replaced;
- not conflict with anything already in the facilitator's mempool.

What remains is a **race double-spend**: the payer sends a conflicting transaction to other nodes or directly to a miner at the same moment. Full-RBF is not default policy, but some miners may run it. 0-conf is therefore a risk decision priced by §7.1, not a guarantee. Facilitators SHOULD connect their node to well-connected peers, and MAY watch for conflicts for a few seconds before returning `success: true` on large 0-conf amounts.

## 13. Error codes

These follow the x402 convention `invalid_exact_<network family>_<reason>`. Core x402 codes are used unchanged where they fit.

| Code | When |
| --- | --- |
| `invalid_x402_version` | `x402Version ≠ 2` |
| `invalid_scheme` | `scheme ≠ "exact"` |
| `invalid_network` | network not supported by this facilitator |
| `invalid_payment_requirements` | bad `extra`, `amount`, `payTo`, or flow/confirmation combination |
| `invalid_exact_dogecoin_requirements_mismatch` | `accepted` ≠ `paymentRequirements` |
| `invalid_exact_dogecoin_asset_mismatch` | `asset ≠ "DOGE"` |
| `invalid_exact_dogecoin_expired` | past `validBefore` |
| `invalid_exact_dogecoin_transaction_malformed` | bad hex or encoding, or duplicate inputs |
| `invalid_exact_dogecoin_transaction_too_large` | more than 100 kB or more than 100 inputs |
| `invalid_exact_dogecoin_nonstandard` | version, or an output type or value Core will not relay |
| `invalid_exact_dogecoin_rbf_signaled` | a non-final sequence at 0-conf |
| `invalid_exact_dogecoin_locktime` | locktime not final |
| `invalid_exact_dogecoin_binding_missing` | no `OP_RETURN` |
| `invalid_exact_dogecoin_binding_mismatch` | wrong or multiple `OP_RETURN`, or wrong nonce |
| `invalid_exact_dogecoin_recipient_mismatch` | zero or several outputs to `payTo` |
| `invalid_exact_dogecoin_amount_mismatch` | the `payTo` output ≠ `amount` |
| `invalid_exact_dogecoin_unsupported_input` | an input that is not P2PKH |
| `invalid_exact_dogecoin_sighash_type` | not `SIGHASH_ALL` |
| `invalid_exact_dogecoin_script_invalid` | bad signature or pubkey, or Core script check failed |
| `invalid_exact_dogecoin_input_missing` | prevout unknown or already spent (including in the mempool) |
| `invalid_exact_dogecoin_input_unconfirmed` | unconfirmed prevout at 0-conf |
| `invalid_exact_dogecoin_input_immature` | immature coinbase |
| `invalid_exact_dogecoin_fee_too_low` / `_fee_too_high` | §10 |
| `insufficient_funds` | outputs exceed inputs |
| `invalid_exact_dogecoin_nonce_used` | (settle) the nonce is already claimed by a different transaction |
| `invalid_exact_dogecoin_input_claimed` | an outpoint is already claimed by another request |
| `duplicate_settlement` | a second settle for a nonce that is already settled or in flight |
| `settlement_pending` | broadcast with an unknown outcome, or confirmations not yet reached |
| `invalid_transaction_state` | Core refused the broadcast |
| `unexpected_verify_error` / `unexpected_settle_error` | node unreachable, RPC fault |

## 14. Security considerations

- **Signed transaction = bearer instrument.** Anyone who sees the `PAYMENT-SIGNATURE` header can broadcast the transaction, and it pays only `payTo`, which is the intended effect. TLS is REQUIRED. Servers MUST NOT log the header to places readable by third parties before settlement.
- **Facilitator trust.** The facilitator cannot redirect funds, since outputs are signed with `SIGHASH_ALL`. It can, however, broadcast a payment for which the resource was not served. Payers trust the resource server and facilitator not to settle without delivering, as with every x402 scheme. Self-hosting the facilitator next to the resource server (Appendix A) removes the third party.
- **Wallet prompts.** Wallets SHOULD show the payer the `payTo`, `amount`, fee, and `resource.url`, and SHOULD warn when the `payTo` output is not the largest non-change output.
- **Node trust.** All checks in §8.3 trust the facilitator's own Dogecoin Core node. It MUST be a fully validating node the operator controls, not a public RPC.
- **Fee sniping and pinning.** These are not relevant at 0-conf because replacement is refused. For `minConfirmations ≥ 1` with RBF allowed, a payer can replace with a higher fee to a different recipient before confirmation; the depth check then fails and `settlement_pending` turns into a timeout. No goods are delivered.
- **Denial of service.** `/verify` costs two RPCs per input. Facilitators SHOULD rate-limit per IP and cap inputs (100 here).
- **Address reuse.** One `payTo` for all requests is fine: the nonce binding separates payments. Servers MAY rotate addresses for privacy.
- **Key material.** Facilitators need no private keys. The reference verifier never touches a wallet. `signrawtransaction` is called with an empty key list.

## 15. Non-goals

- **Not part of ÐLand / ÐMaps ([github.com/jonheaven/dmaps](https://github.com/jonheaven/dmaps)) or any indexer consensus.** An x402 payment is never an inscription, claim, transfer or protocol message, and indexers MUST NOT interpret the `x402` `OP_RETURN` as one. Paying for an API call never grants, moves or proves a ÐLand parcel. ÐMaps state roots and proofs stay free to read (Appendix A).
- **Not for casino, ÐLotto or other value games.** Those have their own on-chain rules and payment paths, and they do not use x402.
- **No token assets.** DRC-20, Doginals, Dunes, and wrapped DOGE on other chains are out of scope. DOGE on other chains is covered by those chains' own `exact` rules.
- **No custody, balances, channels, or streaming.** Every payment is one on-chain transaction.
- **No `upto` scheme or escrow flow.**
- **No consensus or relay changes** to Dogecoin.

## 16. Upstream

Getting this into x402-foundation/x402 means opening a discussion that proposes `exact` on `bip122:1a91e3dace36e2be3bf030a65679fe82` and `bip122:bb0a78264637406b6360aad926284d54`. Then comes a PR adding `specs/schemes/exact/scheme_exact_dogecoin.md` with sections 2–13 of this document, in the layout of the other `scheme_exact_*.md` files. The `bip122` namespace would also cover Bitcoin, Litecoin and other legacy-UTXO chains with small changes: no Dogecoin dust fee, and segwit inputs.

---

## Appendix A — Integration points in the Dogex / command.dog ecosystem (non-normative)

Nothing below is implemented by this document. These are candidate places in the author's own services (Dogex, command.dog, drok.lol, doge.watch), for a later decision.

| Service | Candidate paid endpoints | Stays free |
| --- | --- | --- |
| **Dogex** | heavy or bulk reads: full exports, historical scans, large paginated queries, bulk inscription content | `dmaps-state` roots, proof and verification endpoints, single-item lookups, health checks. Anything an indexer or a light client needs to check ÐLand/ÐMaps state MUST stay free. |
| **command.dog** | can host the facilitator (`/x402/verify`, `/x402/settle`, `/x402/supported`), beside its own Dogecoin Core RPC | — |
| **drok.lol** | per-call or per-token AI usage priced in DOGE, as an alternative to its existing payment path | The existing payment path is unchanged. x402 would be a separate path with its own records. |
| **doge.watch** | alerting or watch-list API calls above a free quota | basic public pages |

### A.1 Client flow with Dojak / MyDoge

1. `GET` the resource and receive `402` with `PAYMENT-REQUIRED`. Decode it and pick the `accepts[]` entry with `network` = Dogecoin mainnet.
2. Select confirmed UTXOs: a list from the wallet, or the client's own indexer, filtered to ≥ 1 confirmation and P2PKH.
3. Build a PSBT:
   - inputs: each with `nonWitnessUtxo` (the full previous transaction, which Dogecoin PSBT signers require) and `sequence = 0xffffffff`;
   - outputs: `payTo` for exactly `amount`, the `OP_RETURN` binding from §6, and change ≥ 0.01 DOGE (or fold sub-dust change into the fee);
   - `version = 1` (or 2), `locktime = 0`;
   - fee = `ceil(estimated size × 1,000,000 / 1000)` koinu, at least, assuming ~148 bytes per input and 34 per P2PKH output.
4. Ask the wallet to sign all inputs with `SIGHASH_ALL`. With Dojak, use its PSBT signing call. With MyDoge, use its `signPsbt`-style request. *Confirm the exact method names and options against each wallet's current API before shipping.* Ask the wallet **not** to broadcast.
5. Finalize the PSBT and extract the raw transaction hex, then lowercase it.
6. Retry the request with `PAYMENT-SIGNATURE: base64(JSON(PaymentPayload))`.
7. Read `PAYMENT-RESPONSE` for the txid. On `settlement_pending`, poll with backoff until `maxTimeoutSeconds`.

### A.2 Facilitator flow with Dogecoin Core

- Use a local `dogecoind` 1.14.9 with RPC on localhost. `-txindex=1` is RECOMMENDED: it lets `getrawtransaction` find confirmed prevouts, which gives exact values, and the confirmation fallback in §9.1. Without it, `verify.mjs` falls back to `gettxout` values; those are floats and are accepted only below 1,000,000 DOGE.
- The wallet can be disabled. `signrawtransaction` with an empty key list must still work for rule 20; if a build lacks it, set `coreScriptCheck: false` in `verify.mjs` and rely on the local P2PKH check.
- Wire `verify.mjs` behind the three HTTP routes: `verifyWithCore`, `settleWithCore`, and `supportedKinds`. Pass a shared claim store when running more than one instance.
- Run it separately from any indexer process. Settling payments needs only RPC reads and `sendrawtransaction`, and never touches indexer state.

## Appendix B — Changelog

- **0.1.0** (2026-11-17): first draft.
