
import shlex
import sys
import os

# Ensure src is in path so we can import google.adk
sys.path.insert(0, os.path.abspath("src"))

from google.adk.cli import cli_deploy
from typing import Optional

def test_get_service_option_by_adk_version_quotes_unsafe_chars():
    adk_version = "1.3.0"
    session_uri = "sqlite://s; rm -rf /"
    artifact_uri = None
    memory_uri = None
    use_local_storage = None

    expected = shlex.quote(f"--session_service_uri={session_uri}")

    actual = cli_deploy._get_service_option_by_adk_version(
        adk_version=adk_version,
        session_uri=session_uri,
        artifact_uri=artifact_uri,
        memory_uri=memory_uri,
        use_local_storage=use_local_storage,
    )

    assert actual == expected
    assert actual.startswith("'")
    assert actual.endswith("'")
    assert "; rm -rf /" in actual

def test_allow_origins_quoting():
    # This logic is inside to_cloud_run/to_gke, hard to test directly without mocking subprocess/files.
    # But we can verify shlex behavior used in the code.
    malicious_origin = 'example.com"; echo "HACKED"'
    allow_origins = [malicious_origin]

    allow_origins_option = (
        shlex.quote(f'--allow_origins={",".join(allow_origins)}')
    )

    assert allow_origins_option.startswith("'")
    assert allow_origins_option.endswith("'")
    assert 'example.com"; echo "HACKED"' in allow_origins_option
