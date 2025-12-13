import subprocess
import json
import os
import hashlib
from functools import lru_cache

TRIVY_DB_PATH = r"C:\Users\hieu\AppData\Local\trivy\db\metadata.json"

def get_trivy_db_timestamp():
    """
    Return Trivy vulnerability DB timestamp (UpdatedAt).
    """
    try:
        if not os.path.exists(TRIVY_DB_PATH):
            print(f"Warning: Trivy DB metadata not found at {TRIVY_DB_PATH}")
            return None

        with open(TRIVY_DB_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)

        ts = meta.get("UpdatedAt") or meta.get("DownloadedAt")
        if not ts:
            print("Warning: UpdatedAt not found in metadata.json")
        return ts

    except Exception as e:
        print(f"Error reading Trivy DB metadata: {e}")
        return None


def get_image_digest(image_name):
    """
    Get Docker image digest: sha256:xxxxxx
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format={{.Id}}", image_name],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return result.stdout.strip()

        print(f"Warning: docker inspect failed for {image_name}: {result.stderr}")
        return None

    except Exception as e:
        print(f"Error getting image digest: {e}")
        return None


@lru_cache(maxsize=128)
def get_cache_key(image_name):
    """
    Generate cache key based on image digest + Trivy DB timestamp.
    """
    digest = get_image_digest(image_name)
    ts = get_trivy_db_timestamp()

    if not digest or not ts:
        print("Warning: Cannot generate cache key (missing digest or timestamp)")
        return None

    raw = f"{digest}|{ts}"
    return hashlib.sha256(raw.encode()).hexdigest()
