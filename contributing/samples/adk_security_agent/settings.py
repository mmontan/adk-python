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
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env", override=True)

GITHUB_BASE_URL = "https://api.github.com"
GITHUB_GRAPHQL_URL = GITHUB_BASE_URL + "/graphql"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
  raise ValueError("GITHUB_TOKEN environment variable not set")

OWNER = os.getenv("OWNER", "google")
REPO = os.getenv("REPO", "adk-python")
PULL_REQUEST_NUMBER = os.getenv("PULL_REQUEST_NUMBER")

IS_INTERACTIVE = os.getenv("INTERACTIVE", "1").lower() in ["true", "1"]

# Dev mode: run the full analysis but never write to GitHub (no comments, no
# labels). Results are shown locally only. Useful for testing the agent without
# side-effects on a real PR.
DEV_MODE = os.environ.get("DEV_MODE", "0").lower() in ["true", "1"]
