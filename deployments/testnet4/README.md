# Testnet4 Deployment

Deployed: 2026-03-10

## Program

| Field | Value |
|-------|-------|
| Program ID (base58) | `8t9HbEkfgYLgDbmPy1nLsQKagoS1mEkTv6Co9fvZcAch` |
| Program ID (hex) | `751bcc7e4b7a69d64f68b22580ef270d9c1134ce7d0ab8aacf569bb4ec09d772` |

## Factory

| Field | Value |
|-------|-------|
| Address (base58) | `9mx2q1tCkAbkQqVb9WzzURiqcCvitwCD7NZuHoaMfgyq` |
| Address (hex) | `94b280a86e216d3503d288e78818e2efdb053569fda30c1e9fd6624db77ab59a` |
| UTXO | `e720dfca01370522ae80c4f486dd707ca5fc9dadab5007fc9c3c450ba8169b98:0` |
| BTC Address | `tb1pjjtsr22r335ysru63ne8szh3wlks565k0mgcxg05lkvfckcdte6qcgsuvk` |

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
arch-cli show 8t9HbEkfgYLgDbmPy1nLsQKagoS1mEkTv6Co9fvZcAch  # Program
arch-cli show 9mx2q1tCkAbkQqVb9WzzURiqcCvitwCD7NZuHoaMfgyq  # Factory
```
