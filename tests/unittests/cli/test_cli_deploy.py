# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import shutil
import tempfile
from unittest.mock import patch
import pytest
from google.adk.cli import cli_deploy

class TestCliDeploy:
    @pytest.fixture
    def mock_subprocess(self):
        with patch('subprocess.run') as mock:
            yield mock

    @pytest.fixture
    def mock_rmtree(self):
        # Patch shutil.rmtree to prevent cleanup of temp folder so we can inspect Dockerfile
        with patch('shutil.rmtree') as mock:
            yield mock

    def test_to_cloud_run_sanitization(self, mock_subprocess, mock_rmtree):
        # Setup agent folder
        with tempfile.TemporaryDirectory() as agent_folder:
            # Create a dummy agent folder structure
            # Use a name with space to verify path quoting
            os.makedirs(os.path.join(agent_folder, 'agents', 'my agent'), exist_ok=True)
            with open(os.path.join(agent_folder, 'agent.py'), 'w') as f:
                f.write('pass')
            with open(os.path.join(agent_folder, '__init__.py'), 'w') as f:
                f.write('pass')
            with open(os.path.join(agent_folder, 'requirements.txt'), 'w') as f:
                f.write('pytest')

            # Setup temp folder for deployment artifact
            temp_deploy_folder = tempfile.mkdtemp()

            try:
                cli_deploy.to_cloud_run(
                    agent_folder=agent_folder,
                    project='my-project',
                    region='us-central1',
                    service_name='my-service',
                    app_name='my agent',
                    temp_folder=temp_deploy_folder,
                    port=8080,
                    trace_to_cloud=False,
                    otel_to_cloud=False,
                    with_ui=False,
                    log_level='INFO',
                    verbosity='INFO',
                    adk_version='1.0.0',
                    allow_origins=['https://example.com', '$(touch /tmp/pwned)'],
                    session_service_uri='sqlite:///$(rm -rf /).db',
                    artifact_service_uri=None,
                    memory_service_uri=None,
                    use_local_storage=False,
                    a2a=False
                )

                # Check Dockerfile content
                dockerfile_path = os.path.join(temp_deploy_folder, 'Dockerfile')
                with open(dockerfile_path, 'r') as f:
                    content = f.read()

                # Verify allow_origins quoting - single quotes for shell safety
                assert "--allow_origins='$(touch /tmp/pwned)'" in content
                assert "--allow_origins=https://example.com" in content

                # Verify session_service_uri quoting
                assert "--session_db_url='sqlite:///$(rm -rf /).db'" in content

                # Verify RUN command path quoting (should be quoted because of space)
                assert "RUN pip install -r '/app/agents/my agent/requirements.txt'" in content

            finally:
                # Manual cleanup because shutil.rmtree is mocked
                if os.path.exists(temp_deploy_folder):
                    # We need to call the real rmtree.
                    # Since shutil.rmtree is mocked, we can use os.system or similar,
                    # or temporarily stop the patch, but the patch is in the fixture.
                    # We can use os.walk to delete.
                    for root, dirs, files in os.walk(temp_deploy_folder, topdown=False):
                        for name in files:
                            os.remove(os.path.join(root, name))
                        for name in dirs:
                            os.rmdir(os.path.join(root, name))
                    os.rmdir(temp_deploy_folder)

    def test_to_gke_sanitization(self, mock_subprocess, mock_rmtree):
        # Similar test for GKE to ensure changes were applied there too
        with tempfile.TemporaryDirectory() as agent_folder:
            os.makedirs(os.path.join(agent_folder, 'agents', 'my agent'), exist_ok=True)
            with open(os.path.join(agent_folder, 'agent.py'), 'w') as f:
                f.write('pass')
            with open(os.path.join(agent_folder, '__init__.py'), 'w') as f:
                f.write('pass')

            temp_deploy_folder = tempfile.mkdtemp()

            try:
                cli_deploy.to_gke(
                    agent_folder=agent_folder,
                    project='my-project',
                    region='us-central1',
                    cluster_name='my-cluster',
                    service_name='my-service',
                    app_name='my agent',
                    temp_folder=temp_deploy_folder,
                    port=8080,
                    trace_to_cloud=False,
                    otel_to_cloud=False,
                    with_ui=False,
                    log_level='INFO',
                    adk_version='1.0.0',
                    allow_origins=['$(touch /tmp/pwned)'],
                    session_service_uri=None,
                    artifact_service_uri=None,
                    memory_service_uri=None,
                    use_local_storage=False,
                    a2a=False
                )

                dockerfile_path = os.path.join(temp_deploy_folder, 'Dockerfile')
                with open(dockerfile_path, 'r') as f:
                    content = f.read()

                assert "--allow_origins='$(touch /tmp/pwned)'" in content

            finally:
                if os.path.exists(temp_deploy_folder):
                    for root, dirs, files in os.walk(temp_deploy_folder, topdown=False):
                        for name in files:
                            os.remove(os.path.join(root, name))
                        for name in dirs:
                            os.rmdir(os.path.join(root, name))
                    os.rmdir(temp_deploy_folder)
