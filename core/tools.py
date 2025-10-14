import subprocess
import sys
import json

def run_trivy(image):
    """Run Trivy scan on the specified Docker image, return results as JSON."""
    try:
        # Trước:
        # result = subprocess.run(
        #     ["trivy", "image", "-f", "json", "-q", image],
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
        #     text=True,
        #     check=True,
        # )
        # Sau (đúng UP022):
        result = subprocess.run(
            ["trivy", "image", "-f", "json", "-q", image],
            capture_output=True,  # thay cho stdout/stderr = PIPE
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error while running Trivy: {e.stderr}", file=sys.stderr)
        sys.exit(1)