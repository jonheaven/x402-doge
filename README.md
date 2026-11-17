# x402-doge

**x402 payments for Dogecoin.** This defines the x402 v2 `exact` scheme on the Dogecoin (`bip122`) network: a draft spec plus a reference verifier.

> **Status: Draft 0.1.0.** This is not reviewed by the x402 maintainers. The reference verifier has **not been run or tested** yet, and the example transaction is illustrative. Don't put real money behind this until there are signed testnet vectors.

[x402](https://github.com/coinbase/x402) (now maintained under [x402-foundation](https://github.com/x402-foundation/x402)) brings back HTTP `402 Payment Required`. A server answers an unpaid request with machine-readable payment terms. The client pays and retries, and a facilitator verifies and settles the payment. Existing schemes mostly move USDC on EVM chains and Solana. This repo adds plain DOGE.

## How it works

1. The server responds `402` with a `PAYMENT-REQUIRED` header listing `accepts[]` entries. A Dogecoin entry looks like this:

   ```json
   {
     "scheme": "exact",
     "network": "bip122:1a91e3dace36e2be3bf030a65679fe82",
     "amount": "100000000",
     "asset": "DOGE",
     "payTo": "D…",
     "maxTimeoutSeconds": 120,
     "extra": {
       "assetTransferMethod": "rawTransaction",
       "nonce": "3c9e1f0a7b5d4e2f8a6c1b0d9e7f5a34",
       "validBefore": "1794936720",
       "minConfirmations": 0
     }
   }
   ```

2. The client's wallet (for example Dojak or MyDoge) signs an ordinary Dogecoin transaction. It pays exactly `amount` koinu to `payTo` and carries one `OP_RETURN` (`6a 15 "x402" 01 <nonce>`) binding it to this request. The client retries with the signed raw transaction in `PAYMENT-SIGNATURE`.
3. A facilitator backed by its own Dogecoin Core 1.14.x node runs `/verify` and `/settle`. It checks outputs, signatures, fees and dust, claims the nonce and the spent coins so the same payment can't be used twice, broadcasts, and returns the txid in `PAYMENT-RESPONSE`.

Small payments clear on 0-conf, with no RBF signal and confirmed inputs only. Larger ones set `minConfirmations` with `paymentFlow: "upfront"`. Dogecoin blocks are about one minute.

There is no new chain logic, token, custody or bridge. A payment is one standard Dogecoin transaction.

## Contents

| Path | |
| --- | --- |
| [`spec.md`](./spec.md) | The normative spec: networks, requirements, payload, binding, verification, settlement and dedup, fees and dust (Core 1.14.9), failure and refund, error codes, security, non-goals, client and facilitator flows. |
| [`verify.mjs`](./verify.mjs) | Reference verifier and settler. Node 18+, no dependencies. Exports `verifyWithCore`, `settleWithCore`, `supportedKinds` and the pure checks. You pass in `rpc(method, params)` for your `dogecoind`. **Untested.** |
| [`examples/`](./examples/) | x402 v2 JSON: `PaymentRequired`, `PaymentPayload`, verify and settle bodies and responses, and `/supported`. The addresses and transaction are placeholders, so don't send DOGE to them. |
| [`CHANGELOG.md`](./CHANGELOG.md) | Version history. |

## Before trusting the verifier

- Signature and sighash code (ECDSA via `node:crypto`) has not been exercised against real transactions yet.
- It needs RIPEMD-160 from Node's OpenSSL. Some OpenSSL 3 builds disable it, and the verifier then fails with a clear error.
- It uses `signrawtransaction hex [] []` as a script check, because 1.14 has no `testmempoolaccept`. Set `coreScriptCheck: false` if your node can't run it.
- `-txindex=1` is recommended for exact prevout values.
- The built-in claim store is in-memory. Multiple facilitator instances need a shared atomic store such as SQL or Redis.

Testnet vectors, issues and PRs are welcome.

## Non-goals

This is a payment rail only. It is not part of ÐMaps / ÐLand or any indexer consensus, and indexers ignore the `x402` `OP_RETURN`. On-chain games don't use it. DRC-20 and other tokens are out of scope. See [spec.md §15](./spec.md#15-non-goals).

## Related

- [coinbase/x402](https://github.com/coinbase/x402) / [x402-foundation/x402](https://github.com/x402-foundation/x402): the x402 protocol and the v2 spec this follows.
- [jonheaven/dmaps](https://github.com/jonheaven/dmaps): sibling open spec for ÐMaps + ÐLand, the real-world land layer on Dogecoin.
- Upstream path: an x402 discussion, then `specs/schemes/exact/scheme_exact_dogecoin.md` (see [spec.md §16](./spec.md#16-upstream)).

## Credits

By Jon Heaven ([@jontype](https://x.com/jontype)). MIT licensed, see [LICENSE](./LICENSE).
