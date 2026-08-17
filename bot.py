import os
import re
import json
import hashlib
import requests
from web3 import Web3
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, filters, ContextTypes

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
SB_KEY = os.getenv("SAFE_BROWSING_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")

# --- blockchain setup (Polygon Amoy) ---
RPC_URL = "https://polygon-rpc.com" # public Amoy RPC
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# the ABI for your contract's reportScam function
CONTRACT_ABI = [{
    "inputs": [{"internalType": "bytes32", "name": "scamHash", "type": "bytes32"}],
    "name": "reportScam",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
}]

def report_onchain(text_to_hash):
    """Hash a scam string and write it to the registry contract."""
    if not (CONTRACT_ADDRESS and PRIVATE_KEY and w3.is_connected()):
        return None
    try:
        account = w3.eth.account.from_key(PRIVATE_KEY)
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=CONTRACT_ABI
        )
        # turn the scam link/address into a bytes32 hash
        scam_hash = hashlib.sha256(text_to_hash.encode()).digest()

        tx = contract.functions.reportScam(scam_hash).build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 200000,
            "gasPrice": w3.eth.gas_price,
        })
        signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        return tx_hash.hex()
    except Exception as e:
        print("On-chain report failed:", e)
        return None

SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + (SB_KEY or "")
BLACKLIST = ["free-airdrop", "claim-reward", "connect-wallet", "metamask-verify", "double-your"]

def check_google(link):
    if not SB_KEY:
        return None
    body = {
        "client": {"clientId": "chainguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": link}],
        },
    }
    try:
        r = requests.post(SB_URL, json=body, timeout=5)
        if r.json().get("matches"):
            return r.json()["matches"][0]["threatType"]
    except Exception:
        return None
    return None

def check_blacklist(link):
    low = link.lower()
    for bad in BLACKLIST:
        if bad in low:
            return bad
    return None

REGISTRY_FILE = "scam_registry.json"

def load_registry():
    """Load the set of known scam hashes from disk."""
    try:
        with open(REGISTRY_FILE, "r") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_to_registry(scam_hash):
    """Add a confirmed scam hash and persist it."""
    known = load_registry()
    known.add(scam_hash)
    with open(REGISTRY_FILE, "w") as f:
        json.dump(list(known), f)

def is_known_scam(text):
    """READ-BACK: has this exact link/address been reported before?"""
    scam_hash = hashlib.sha256(text.encode()).hexdigest()
    return scam_hash in load_registry()

def add_known_scam(text):
    """Record a newly confirmed scam so future posts get flagged instantly."""
    scam_hash = hashlib.sha256(text.encode()).hexdigest()
    save_to_registry(scam_hash)
    return scam_hash

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    links = re.findall(r'https?://\S+', text)
    addresses = re.findall(r'0x[a-fA-F0-9]{40}', text)

    if not links and not addresses:
        return

    reply = "🛡️ ChainGuard scan:\n"

    for link in links:
        if is_known_scam(link):
            reply += f"\n🚨 KNOWN SCAM: {link}\n     ↳ previously reported to the registry"
            continue

        threat = check_google(link)
        word = check_blacklist(link)
        if threat:
            add_known_scam(link)
            report_onchain(link)
            reply += f"\n🚨 DANGER: {link}\n     ↳ Google flagged: {threat}  ·  added to registry"
        elif word:
            add_known_scam(link)
            report_onchain(link)
            reply += f"\n⚠️ SUSPICIOUS: {link}\n     ↳ matched '{word}'  ·  added to registry"
        else:
            reply += f"\n✅ Looks clean: {link}"

    for addr in addresses:
        if is_known_scam(addr):
            reply += f"\n🚨 KNOWN SCAM CONTRACT: {addr}\n     ↳ previously reported"
        else:
            reply += f"\n📄 Contract: {addr} (verify before interacting)"

    await update.message.reply_text(reply)

app = ApplicationBuilder().token(TOKEN).build()
app.add_handler(MessageHandler(filters.TEXT, scan))
print("ChainGuard online...")
app.run_polling()