# x402-doge examples

JSON objects for the `exact` scheme on Dogecoin mainnet (`bip122:1a91e3dace36e2be3bf030a65679fe82`). Field names follow x402 v2 exactly (`specs/x402-specification-v2.md` in x402-foundation/x402).

| File | What it is |
| --- | --- |
| `payment-required.json` | `PaymentRequired` for a 1 DOGE read, 0-conf, `authorization` flow. HTTP: base64 in `PAYMENT-REQUIRED`. |
| `payment-required-upfront.json` | `PaymentRequired` for a 25 DOGE purchase that settles after 2 confirmations, `upfront` flow. |
| `payment-payload.json` | `PaymentPayload` answering `payment-required.json`. HTTP: base64 in `PAYMENT-SIGNATURE`. |
| `verify-request.json` | Body of `POST /verify` (and `POST /settle`). |
| `verify-response-*.json` | `VerifyResponse`, valid and invalid. |
| `settle-response-*.json` | `SettleResponse`: success, `settlement_pending`, failure. HTTP: base64 in `PAYMENT-RESPONSE`. |
| `supported.json` | `GET /supported` for a facilitator offering mainnet and testnet. |

**The transaction in `payment-payload.json` is illustrative.** Its structure is real and decodes: version 1, one input with `nSequence = 0xffffffff`, outputs `[0]` 1 DOGE to `payTo`, `[1]` the binding `OP_RETURN 15 78343032 01 3c9e1f0a7b5d4e2f8a6c1b0d9e7f5a34`, `[2]` 4.99 DOGE change, `nLockTime = 0`, 258 bytes, txid `26c42ddc597e60f210f8a15098edff637126a833a980efa5e8fb4662e56d37d9`. The previous output, the public key and the signature are placeholders, so a facilitator rejects it (`invalid_exact_dogecoin_input_missing`, or `invalid_exact_dogecoin_script_invalid`). The addresses are well-formed Base58Check with made-up hashes; nobody holds their keys. Do not send DOGE to them.

Signed vectors from a real testnet payment belong in a top-level `vectors/` directory once one has been made with Dojak or MyDoge.
