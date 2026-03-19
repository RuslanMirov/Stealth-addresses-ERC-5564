# stealth-erc5564

Privacy-preserving ETH payments. Alice pays Bob without anyone on-chain knowing Bob received anything.

## How it works

**Bob** generates two key pairs once and publishes the public halves as his *meta-address*:
- `spendingKey` — controls funds
- `viewingKey` — read-only, safe to share with accountants

**Alice** picks a random number `r`, computes a shared secret via ECDH with Bob's viewing key, and derives a fresh one-time address that only Bob can find. She deploys a vault owned by that address and sends ETH into it — all in one transaction.

**Bob** scans `Announcement` events. For each one he does a cheap 1-byte `viewTag` check that skips 255/256 entries before doing the full ECDH. When he finds a match, he reconstructs the private key: `stealthPriv = spendingPriv + sharedSecret`.

**Withdrawal** — Bob signs a typed `WithdrawRequest` offline with `stealthPriv`. A public relayer submits it on-chain and takes a small fee. Bob never broadcasts from any known address.

```
Bob      → publishes metaAddress (spendPub + viewPub)
Alice    → computeStealthAddress(metaAddress) → stealthAddr, R, viewTag
Alice    → factory.deployAndSend(stealthAddr, R, viewTag) {value: 1 ETH}
Bob      → scans Announcement logs, finds vault via viewTag + ECDH
Bob      → signs WithdrawRequest offline
Relayer  → vault.withdrawWithSig(...) → fee to relayer, rest to Bob
```

## Why the vault?

Alice's transaction already funds the stealth address — Bob has the private key and could spend from it directly. The vault adds one extra guarantee: **the stealth address never appears as `msg.sender` in any transaction.**

Without vault:
```
stealth address received ETH  ← visible on-chain
stealth address sent ETH      ← visible on-chain as sender
                                 → two data points, linkable
```

With vault + relayer:
```
stealth address = owner field inside the contract (never a tx sender)
relayer submits withdrawWithSig()  ← only the relayer is visible
Bob's destination receives ETH     ← no link to the stealth address
```

The vault also protects against a malicious relayer: the EIP-712 signature pins `to`, `amount`, `fee`, `deadline`, and `nonce` — the relayer cannot redirect funds or replay the signature.

If the extra on-chain privacy doesn't matter for your use case, you can skip the vault and send ETH directly to the stealth address. Bob can spend it normally. The anonymity from Alice is preserved either way.

## Stack

- **Solidity 0.8.24** — `StealthAnnouncer` (event log), `StealthVault` (EIP-712 wallet), `StealthFactory` (EIP-1167 clone + announce in one tx, ~153k gas)
- **secp256k1 + sha256** — ERC-5564 scheme 1 via `@noble/curves` / `@noble/hashes`
- **Hardhat + ethers v6**

## Usage

```bash
npm install
npx hardhat test
npx hardhat run scripts/deploy.js --network localhost
```