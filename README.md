# ChainGuard — TCS 332 Project
### A Telegram Bot for Real-Time Crypto Scam Detection with On-Chain Registry

**Course:** Fundamentals of Information Security (TCS 332)

---

## Overview
ChainGuard is a Telegram bot that protects crypto communities from scams. It scans every link and smart-contract address posted in a chat, checks each one against Google's live threat database and its own scam-detection rules, and warns the group in real time. Confirmed scams are fingerprinted using SHA-256 and recorded on a smart contract deployed live on the Polygon blockchain — a public, tamper-proof registry.

**Live Smart Contract:** Deployed and verified on Polygon Mainnet (address `0xBEf...aaeFC`)

---

## Tech Stack
| Component | Technology |
|-----------|-----------|
| Language | Python 3 |
| Bot Framework | python-telegram-bot |
| Threat Detection | Google Safe Browsing API + heuristic blacklist |
| Hashing | SHA-256 (hashlib) |
| Persistence | JSON registry |
| Smart Contract | Solidity (^0.8.20) |
| Blockchain | Polygon Mainnet |
| Wallet / Signing | MetaMask + web3.py |
| Secrets Management | python-dotenv (.env) |

---

## Module-Wise Breakdown

### Module 1 — Message Scanning & Parsing
Receives every message via the Telegram Bot API and extracts URLs and Ethereum contract addresses using regular expressions.
- URL pattern: `https?://\S+`
- Contract address pattern: `0x[a-fA-F0-9]{40}` (0x followed by exactly 40 hex characters)

### Module 2 — Threat Detection (Defense in Depth)
Two-layer detection so neither layer's blind spot leaves users exposed:
- **Google Safe Browsing API** — checks URLs against Google's live global database of known malicious sites.
- **Heuristic blacklist** — catches crypto-specific scam patterns (fake airdrops, wallet-connect phishing, link shorteners) a general-purpose tool may miss.

### Module 3 — Persistent Scam Registry (Read-Back)
Maintains a local JSON registry of confirmed scams, stored as SHA-256 hashes.
- Incoming links are checked against the registry first (fast path / cache pattern).
- Known scams are flagged instantly, without re-querying external services.
- The registry persists across restarts.

### Module 4 — On-Chain Registry (Smart Contract)
A Solidity contract (`ScamRegistry.sol`) deployed and verified on Polygon Mainnet.
- `mapping(bytes32 => bool)` stores scam hashes on-chain.
- `reportScam(bytes32)` records a confirmed scam (state-changing, costs gas).
- `checkScam(bytes32)` reads whether a hash is a known scam (view function, free).
- The bot writes via web3.py. Only a SHA-256 hash is stored on-chain, never raw data.

### Module 5 — Secrets Management
All sensitive values (bot token, API key, wallet private key) are stored in a git-ignored `.env` file and loaded at runtime via python-dotenv — never hardcoded.

---

## How to Run
1. Install dependencies: `pip install python-telegram-bot requests web3 python-dotenv`
2. Create a `.env` file with `BOT_TOKEN`, `SAFE_BROWSING_KEY`, `CONTRACT_ADDRESS`, `PRIVATE_KEY`
3. Run: `python bot.py`

---

## Team
- Aarav Sharma — Section F, Roll No 02
- Karnika Jain - section E
