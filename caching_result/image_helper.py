import subprocess
import json
import hashlib

def get_image_digest(image_name):
    """
    Get Docker image digest (SHA256 ID).
    Returns digest string (e.g., "sha256:abc123...") or None if not found.
    """
    try:
        # docker inspect --format='{{.Id}}'
        result = subprocess.run(
            ["docker", "inspect", "--format={{.Id}}", image_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            digest = result.stdout.strip()
            return digest
        else:
            print(f"Warning: docker inspect failed for {image_name}: {result.stderr}")
            return None
    except FileNotFoundError:
        print("Warning: docker command not found")
        return None
    except Exception as e:
        print(f"Error getting image digest: {e}")
        return None

def hash_trivy_output(trivy_json_str):
    """
    Hash Trivy JSON output to detect changes.
    Returns SHA256 hash of the output.
    """
    return hashlib.sha256(trivy_json_str.encode()).hexdigest()