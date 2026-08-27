# scanners/container/docker.py
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def scan() -> List[Dict]:
    """Check for privileged containers and other security issues."""
    errors = []
    try:
        import docker
        client = docker.from_env()
        for container in client.containers.list():
            attrs = container.attrs
            privileged = attrs.get('HostConfig', {}).get('Privileged', False)
            if privileged:
                errors.append({
                    "field_path": f"docker_{container.id[:12]}",
                    "error_type": "PRIVILEGED_CONTAINER",
                    "message": f"Container {container.name} is running in privileged mode"
                })
    except ImportError:
        logger.warning("Docker library not installed – skipping container audit")
    except Exception as e:
        logger.warning(f"Docker scan failed: {e}")
    return errors
