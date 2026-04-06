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

import base64
import sys
from typing import Any

from adk_security_agent.settings import GITHUB_BASE_URL
from adk_security_agent.settings import GITHUB_GRAPHQL_URL
from adk_security_agent.settings import GITHUB_TOKEN
from adk_security_agent.settings import OWNER
from adk_security_agent.settings import REPO
from google.adk.agents.run_config import RunConfig
from google.adk.runners import Runner
from google.genai import types
import requests

headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}

diff_headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3.diff",
}


def run_graphql_query(query: str, variables: dict[str, Any]) -> dict[str, Any]:
  """Executes a GraphQL query."""
  payload = {"query": query, "variables": variables}
  response = requests.post(
      GITHUB_GRAPHQL_URL, headers=headers, json=payload, timeout=60
  )
  response.raise_for_status()
  return response.json()


def get_request(url: str, params: dict[str, Any] | None = None) -> Any:
  """Executes a GET request."""
  response = requests.get(url, headers=headers, params=params, timeout=60)
  response.raise_for_status()
  return response.json()


def get_diff(url: str) -> str:
  """Executes a GET request for a diff."""
  response = requests.get(url, headers=diff_headers, timeout=60)
  response.raise_for_status()
  return response.text


def post_request(url: str, payload: Any) -> dict[str, Any]:
  """Executes a POST request."""
  response = requests.post(url, headers=headers, json=payload, timeout=60)
  response.raise_for_status()
  return response.json()


def error_response(error_message: str) -> dict[str, Any]:
  """Returns an error response."""
  return {"status": "error", "error_message": error_message}


def read_file(file_path: str) -> str:
  """Read the content of the given file."""
  try:
    with open(file_path) as f:
      return f.read()
  except FileNotFoundError:
    print(f"Error: File not found: {file_path}.")
    return ""


def get_github_file_content(file_path: str, ref: str) -> str:
  """Fetch raw file content via GitHub Contents API (base64-decoded).

  Args:
    file_path: Path to the file within the repository.
    ref: The branch, tag, or commit SHA to fetch from.

  Returns:
    The decoded file content as a string, or an empty string on error.
  """
  url = f"{GITHUB_BASE_URL}/repos/{OWNER}/{REPO}/contents/{file_path}"
  try:
    data = get_request(url, {"ref": ref})
    if data.get("encoding") == "base64":
      return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return data.get("content", "")
  except requests.exceptions.RequestException as e:
    print(f"Error fetching file {file_path} at {ref}: {e}")
    return ""


def parse_number_string(number_str: str | None, default_value: int = 0) -> int:
  """Parse a number from the given string."""
  if not number_str:
    return default_value

  try:
    return int(number_str)
  except ValueError:
    print(
        f"Warning: Invalid number string: {number_str}. Defaulting to"
        f" {default_value}.",
        file=sys.stderr,
    )
    return default_value


async def call_agent_async(
    runner: Runner, user_id: str, session_id: str, prompt: str
) -> str:
  """Call the agent asynchronously with the user's prompt."""
  content = types.Content(
      role="user", parts=[types.Part.from_text(text=prompt)]
  )

  final_response_text = ""
  async for event in runner.run_async(
      user_id=user_id,
      session_id=session_id,
      new_message=content,
      run_config=RunConfig(save_input_blobs_as_artifacts=False),
  ):
    if event.content and event.content.parts:
      if text := "".join(part.text or "" for part in event.content.parts):
        if event.author != "user":
          final_response_text += text

  return final_response_text
