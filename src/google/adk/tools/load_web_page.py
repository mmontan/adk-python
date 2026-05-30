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

"""Tool for web browse."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests


def _validate_url(url: str) -> bool:
  """Validates if the URL is safe to browse."""
  try:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
      return False

    hostname = parsed.hostname
    if not hostname:
      return False

    # Check if hostname is an IP literal
    try:
      ip = ipaddress.ip_address(hostname)
      if (
          ip.is_loopback
          or ip.is_private
          or ip.is_link_local
          or ip.is_reserved
          or ip.is_multicast
      ):
        return False
      return True
    except ValueError:
      pass  # Not an IP literal

    # Resolve hostname to IP
    try:
      ip_str = socket.gethostbyname(hostname)
      ip = ipaddress.ip_address(ip_str)
      if (
          ip.is_loopback
          or ip.is_private
          or ip.is_link_local
          or ip.is_reserved
          or ip.is_multicast
      ):
        return False
    except socket.error:
      return False

    return True
  except Exception:  # pylint: disable=broad-exception-caught
    return False


def load_web_page(url: str) -> str:
  """Fetches the content in the url and returns the text in it.

  Args:
      url (str): The url to browse.

  Returns:
      str: The text content of the url.
  """
  from bs4 import BeautifulSoup

  if not _validate_url(url):
    return f'Failed to fetch url: {url} (URL not allowed)'

  # Set allow_redirects=False to prevent SSRF attacks via redirection.
  response = requests.get(url, allow_redirects=False, timeout=10)

  if response.status_code == 200:
    soup = BeautifulSoup(response.content, 'lxml')
    text = soup.get_text(separator='\n', strip=True)
  else:
    text = f'Failed to fetch url: {url}'

  # Split the text into lines, filtering out very short lines
  # (e.g., single words or short subtitles)
  return '\n'.join(line for line in text.splitlines() if len(line.split()) > 3)
