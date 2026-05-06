# Testnet4 Deployment

Deployed: 2026-05-06

## Program

| Field | Value |
|-------|-------|
| Program ID (base58) | `AaKCZHQPVaByGTTyhx52iDsEZ1ZAtS5dEKrGxs1FDUA6` |
| Program ID (hex) | `8e41ed4f9f278cd8ebafc6d873803774abd8457b7fb3eb693f23f8e0caa1889b` |

## Factory

| Field | Value |
|-------|-------|
| Address (base58) | `52KUxzgHy7tGsQkTcSceLo2PFhpQ5qfhGZSkN2FbDGcs` |
| Address (hex) | `3bc539f2df1e04046b336dc1b08d584a84c74f2f5e0a9716be5b80382764a1bc` |
| UTXO | `c55af455c63c3a4753379ad478b3db7ff0a3b1e3c6d43ced6ad554a6f1acdaab:0` |
| BTC Address | `tb1pz69d0alpn9hnk5lp5x3y6sxjxnglkfruanmqmywhkjtfcz4g943qqdm8fk` |

## Admin

| Field | Value |
|-------|-------|
| Pubkey (base58) | `HJHAzyLRT5643RbykFPB9UEdpmNfYcMiWjTA7quYj5an` |
| Pubkey (hex) | `f22826990c74d224f87495af0d1d71662e5005b6dac23dda5b0d0b5a35bf1837` |

## Fees

| Type | Amount |
|------|--------|
| Creation | 1000 lamports |
| Transfer | 100 lamports |
| Execute | 100 lamports |

## Endpoints

| Service | URL |
|---------|-----|
| Arch RPC | `https://rpc.testnet.arch.network` |
| Titan | `https://titan.testnet.arch.network` |
| Bitcoin RPC | `http://bitcoin-rpc.test.arch.network:80` |

## Verification

```bash
arch-cli show AaKCZHQPVaByGTTyhx52iDsEZ1ZAtS5dEKrGxs1FDUA6  # Program
arch-cli show 52KUxzgHy7tGsQkTcSceLo2PFhpQ5qfhGZSkN2FbDGcs  # Factory
```
