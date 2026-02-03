
import os
import shutil
import tempfile
from unittest import mock
import pytest
from google.adk.cli import cli_deploy

class TestCliDeploySecurity:

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.agent_dir = os.path.join(self.temp_dir, "my_agent")
        os.makedirs(self.agent_dir)
        # Create minimal agent files
        with open(os.path.join(self.agent_dir, "__init__.py"), "w") as f:
            f.write("")
        with open(os.path.join(self.agent_dir, "agent.py"), "w") as f:
            f.write("")

    def teardown_method(self):
        shutil.rmtree(self.temp_dir)

    @mock.patch("subprocess.run")
    @mock.patch("shutil.rmtree")
    def test_to_cloud_run_injection(self, mock_rmtree, mock_run):
        # Malicious input for allow_origins
        malicious_origin = "foo; rm -rf /"

        # We need to mock _resolve_project to avoid gcloud calls
        # We mock shutil.rmtree to prevent cleanup so we can inspect the file

        # We also need to allow the first rmtree call if it happens (when clearing existing temp folder)
        # But for simplicity, we can just let it mock all rmtree calls.
        # Since our temp folder is unique per test run, it shouldn't exist beforehand.

        with mock.patch("google.adk.cli.cli_deploy._resolve_project", return_value="my-project"):
            cli_deploy.to_cloud_run(
                agent_folder=self.agent_dir,
                project="my-project",
                region="us-central1",
                service_name="test-service",
                app_name="test-app",
                temp_folder=os.path.join(self.temp_dir, "deploy_tmp"),
                port=8080,
                trace_to_cloud=False,
                otel_to_cloud=False,
                with_ui=False,
                log_level="INFO",
                verbosity="INFO",
                adk_version="0.5.0",
                allow_origins=[malicious_origin],
                session_service_uri="memory://; echo hacked", # Also test this
                use_local_storage=False
            )

        dockerfile_path = os.path.join(self.temp_dir, "deploy_tmp", "Dockerfile")
        with open(dockerfile_path, "r") as f:
            content = f.read()

        print(f"Dockerfile Content:\n{content}")

        # Check for injection in allow_origins
        # The malicious string should be quoted or handled safely.
        # In the vulnerable version, it appears raw.
        # We expect failure if it appears raw and unquoted in a way that allows execution.
        # Since we are generating the Dockerfile, we check if the malicious string exists
        # as a command separator.

        # In vulnerable version: --allow_origins=foo; rm -rf /
        # In fixed version, it should be: --allow_origins='foo; rm -rf /' OR --allow_origins="foo; rm -rf /"
        # Or at least escaped.

        # Also check session_service_uri injection
        # Vulnerable: --session_db_url=memory://; echo hacked

        # We assert that the injection attempt is NOT present in its raw executable form.
        # But since we are looking at text, let's just assert that it IS properly quoted.

        # For allow_origins, we also want multiple flags if multiple origins are passed,
        # but here we test injection first.

        # Check if "foo; rm -rf /" is present without quotes surrounding it?
        # It's hard to regex check "not quoted", but we can check if it IS quoted.

        import shlex
        expected_origin = shlex.quote(malicious_origin)
        expected_session = shlex.quote("memory://; echo hacked")

        # If the code is NOT using shlex.quote, these assertions will likely fail
        # (or rather, we check if the RAW string is present).

        # If vulnerable, content contains: --allow_origins=foo; rm -rf /
        # If fixed, content contains: --allow_origins='foo; rm -rf /'

        # Let's assert that the raw string is NOT present in the CMD line unless it's quoted.
        # Actually, simpler: verify that the output matches the safe version.

        assert f"--allow_origins={expected_origin}" in content or f"--allow_origins={malicious_origin}" not in content

        # For session uri (using adk_version 0.5.0 so it uses --session_db_url)
        assert f"--session_db_url={expected_session}" in content or f"--session_db_url=memory://; echo hacked" not in content

    @mock.patch("subprocess.run")
    @mock.patch("shutil.rmtree")
    def test_to_cloud_run_multiple_origins(self, mock_rmtree, mock_run):
        # Multiple valid origins
        origins = ["https://a.com", "https://b.com"]

        with mock.patch("google.adk.cli.cli_deploy._resolve_project", return_value="my-project"):
            cli_deploy.to_cloud_run(
                agent_folder=self.agent_dir,
                project="my-project",
                region="us-central1",
                service_name="test-service",
                app_name="test-app",
                temp_folder=os.path.join(self.temp_dir, "deploy_multi"),
                port=8080,
                trace_to_cloud=False,
                otel_to_cloud=False,
                with_ui=False,
                log_level="INFO",
                verbosity="INFO",
                adk_version="0.5.0",
                allow_origins=origins,
                use_local_storage=True
            )

        dockerfile_path = os.path.join(self.temp_dir, "deploy_multi", "Dockerfile")
        with open(dockerfile_path, "r") as f:
            content = f.read()

        # Check that we have multiple flags
        import shlex
        origin_a = shlex.quote("https://a.com")
        origin_b = shlex.quote("https://b.com")

        # Note: We rely on the implementation order which is iteration order of list
        assert f"--allow_origins={origin_a}" in content
        assert f"--allow_origins={origin_b}" in content

        # Ensure they are separate flags, not comma separated
        assert "https://a.com,https://b.com" not in content
