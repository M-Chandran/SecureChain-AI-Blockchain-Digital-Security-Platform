from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple


_chain_lock = threading.Lock()


def init_blockchain_storage(app) -> None:
    chain_file = Path(app.config["BLOCKCHAIN_JSON"])
    if chain_file.exists():
        return

    genesis_block = {
        "block_number": 0,
        "file_hash": "GENESIS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_hash": "0" * 64,
        "verification_id": "GENESIS",
        "owner_id": "system",
        "record_type": "genesis",
    }
    genesis_block["block_hash"] = _compute_block_hash(genesis_block)
    with chain_file.open("w", encoding="utf-8") as file_obj:
        json.dump([genesis_block], file_obj, indent=2)


def load_chain(chain_file: Path) -> List[Dict[str, str]]:
    with _chain_lock:
        if not chain_file.exists():
            return []
        with chain_file.open("r", encoding="utf-8") as file_obj:
            return json.load(file_obj)


def save_chain(chain_file: Path, chain: List[Dict[str, str]]) -> None:
    with _chain_lock:
        with chain_file.open("w", encoding="utf-8") as file_obj:
            json.dump(chain, file_obj, indent=2)


def create_block(
    chain_file: Path,
    file_hash: str,
    owner_id: str,
    verification_id: str,
    record_type: str = "upload",
) -> Dict[str, str]:
    chain = load_chain(chain_file)
    latest = chain[-1]

    block = {
        "block_number": len(chain),
        "file_hash": file_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_hash": latest["block_hash"],
        "verification_id": verification_id,
        "owner_id": owner_id,
        "record_type": record_type,
    }
    block["block_hash"] = _compute_block_hash(block)
    chain.append(block)
    save_chain(chain_file, chain)
    return block


def validate_chain(chain_file: Path) -> Tuple[bool, List[str]]:
    chain = load_chain(chain_file)
    if not chain:
        return False, ["Blockchain file is empty."]

    issues: List[str] = []
    for index, block in enumerate(chain):
        recalculated = _compute_block_hash(block)
        if block.get("block_hash") != recalculated:
            issues.append(f"Block {index} hash mismatch.")

        if index > 0:
            prev = chain[index - 1]
            if block.get("previous_hash") != prev.get("block_hash"):
                issues.append(f"Block {index} previous hash mismatch.")

    return len(issues) == 0, issues


def find_blocks_by_verification_id(chain_file: Path, verification_id: str) -> List[Dict[str, str]]:
    chain = load_chain(chain_file)
    target = verification_id.strip().upper()
    return [block for block in chain if block["verification_id"].upper() == target]


def latest_block_by_verification_id(chain_file: Path, verification_id: str) -> Dict[str, str] | None:
    blocks = find_blocks_by_verification_id(chain_file, verification_id)
    if not blocks:
        return None
    return blocks[-1]


def blockchain_health(chain_file: Path) -> Dict[str, object]:
    chain = load_chain(chain_file)
    valid, issues = validate_chain(chain_file)
    return {
        "is_valid": valid,
        "issues": issues,
        "total_blocks": len(chain),
        "latest_block_hash": chain[-1]["block_hash"] if chain else None,
    }


def _compute_block_hash(block: Dict[str, str]) -> str:
    material = {
        "block_number": block.get("block_number"),
        "file_hash": block.get("file_hash"),
        "timestamp": block.get("timestamp"),
        "previous_hash": block.get("previous_hash"),
        "verification_id": block.get("verification_id"),
        "owner_id": block.get("owner_id"),
        "record_type": block.get("record_type", "upload"),
    }
    encoded = json.dumps(material, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
