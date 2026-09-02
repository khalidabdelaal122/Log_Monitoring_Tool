"""HMAC-SHA256 baseline signing and verification."""
import hashlib
import hmac
import json
import os
from typing import Protocol

class BaselineLike(Protocol):
    file_path: str
    baseline_hash: str
    file_size: int
    owner_uid: int
    group_gid: int
    permissions: int
    inode: int

class HMACConfigurationError(ValueError):
    """The baseline signing key is missing or unsafe."""

class HMACManager:
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise HMACConfigurationError("LOGGUARD_HMAC_KEY must contain at least 32 bytes")
        self._key = key

    @classmethod
    def from_environment(cls) -> "HMACManager":
        value = os.environ.get("LOGGUARD_HMAC_KEY")
        if not value:
            raise HMACConfigurationError(
                "LOGGUARD_HMAC_KEY is required; generate one with: openssl rand -hex 32")
        return cls(value.encode("utf-8"))

    @staticmethod
    def payload(item: BaselineLike) -> bytes:
        values = {"baseline_hash": item.baseline_hash, "file_path": item.file_path,
                  "file_size": item.file_size, "group_gid": item.group_gid,
                  "inode": item.inode, "owner_uid": item.owner_uid,
                  "permissions": item.permissions}
        return json.dumps(values, sort_keys=True, separators=(",", ":")).encode()

    def sign(self, item: BaselineLike) -> str:
        return hmac.new(self._key, self.payload(item), hashlib.sha256).hexdigest()

    def verify(self, item: BaselineLike, signature: str) -> bool:
        return hmac.compare_digest(self.sign(item), signature)
