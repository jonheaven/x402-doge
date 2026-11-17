# Changelog

## 0.1.0-draft — 2026-11-17

- First public draft of the x402 v2 `exact` scheme on Dogecoin (`bip122:1a91e3dace36e2be3bf030a65679fe82` mainnet, `bip122:bb0a78264637406b6360aad926284d54` testnet).
- `spec.md`:
  - payment terms with `assetTransferMethod: "rawTransaction"`, `nonce`, `validBefore`, `minConfirmations`, `minFeePerKb`;
  - an `OP_RETURN` nonce binding;
  - 0-conf rules (no RBF signal, confirmed inputs) and confirmation tiers;
  - Dogecoin Core 1.14.9 fee and dust rules;
  - nonce and outpoint dedup;
  - failure and refund semantics, error codes, security, non-goals.
- `verify.mjs`: dependency-free reference verifier and settler. **Not yet run or tested.**
- `examples/`: x402 v2 JSON objects with an illustrative transaction (placeholder prevout, key and signature).
