import json
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ALCHEMY_URL = os.getenv("ALCHEMY_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ACCOUNT_ADDRESS = os.getenv("ACCOUNT_ADDRESS")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
CONTRACT_ABI_PATH = Path("contract_abi.json")

_web3 = None
_contract = None
_configured = None


def is_blockchain_configured() -> bool:
    """Return True when env vars and contract ABI are present."""
    global _configured
    if _configured is not None:
        return _configured

    env_ok = all([ALCHEMY_URL, PRIVATE_KEY, ACCOUNT_ADDRESS, CONTRACT_ADDRESS])
    _configured = bool(env_ok and CONTRACT_ABI_PATH.is_file())
    return _configured


def _init_blockchain():
    """Initialize Web3 client and contract on first use."""
    global _web3, _contract

    if not is_blockchain_configured():
        raise RuntimeError(
            "Blockchain not configured. Set ALCHEMY_URL, PRIVATE_KEY, "
            "ACCOUNT_ADDRESS, and CONTRACT_ADDRESS in .env, and add contract_abi.json."
        )

    if _contract is not None:
        return _web3, _contract

    from web3 import Web3

    with CONTRACT_ABI_PATH.open(encoding="utf-8") as f:
        contract_abi = json.load(f)

    _web3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
    _contract = _web3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
    return _web3, _contract


def store_certificate_hash(cert_id, cert_hash):
    if not is_blockchain_configured():
        print("[BLOCKCHAIN] Skipped: blockchain not configured.")
        return None

    web3, contract = _init_blockchain()
    nonce = web3.eth.get_transaction_count(ACCOUNT_ADDRESS)
    try:
        try:
            gas_estimate = contract.functions.storeCertificate(cert_id, cert_hash).estimate_gas(
                {"from": ACCOUNT_ADDRESS}
            )
        except Exception as e:
            print(f"[ERROR] Gas estimate failed: {e}")
            return None

        tx = contract.functions.storeCertificate(cert_id, cert_hash).build_transaction(
            {
                "chainId": 11155111,
                "gas": gas_estimate,
                "gasPrice": web3.to_wei("20", "gwei"),
                "nonce": nonce,
            }
        )
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        return web3.to_hex(tx_hash)
    except Exception as e:
        print(f"[ERROR] Blockchain transaction failed: {e}")
        return None


def verify_certificate(cert_id, cert_hash):
    if not is_blockchain_configured():
        raise RuntimeError("Blockchain not configured.")

    _, contract = _init_blockchain()
    stored_hash = contract.functions.getCertificate(cert_id).call()
    return stored_hash == cert_hash, stored_hash
