# Testnet4 Deployment

Deployed: 2026-05-04

## Program

| Field | Value |
|-------|-------|
| Program ID (base58) | `BKCgdSMMWfEvVf6okHckp4nwbJniqsa428D7xkbCapNL` |
| Program ID (hex) | `993e88bbb8e9c6bf39408905230a70a9986413ed84d964bf20b7b402796ebcc9` |

## Factory

| Field | Value |
|-------|-------|
| Address (base58) | `9aQjvvgjpnsAwp1f2UJZPkX1NmGFqcuGCNoW5tP6yA4k` |
| Address (hex) | `7f6c81550c579302c88c1c8521ce56756bdc3753bb5df70fa18019540bdffaad` |
| UTXO | `43999fb07231e61c4615b8cfcfff592a58bfce8b6a2fd92043fde4bc6f4a71a0:0` |
| BTC Address | `tb1pwt2tgsztjf2e256wl2aggk0rmlhpef246erjnf96j9737fh38fusv53kmj` |

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
arch-cli show BKCgdSMMWfEvVf6okHckp4nwbJniqsa428D7xkbCapNL  # Program
arch-cli show 9aQjvvgjpnsAwp1f2UJZPkX1NmGFqcuGCNoW5tP6yA4k  # Factory
```
