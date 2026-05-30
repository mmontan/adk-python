import unittest
from unittest.mock import patch, MagicMock
from google.adk.tools.load_web_page import load_web_page


class TestLoadWebPage(unittest.TestCase):

  @patch("requests.get")
  @patch("socket.gethostbyname")
  def test_load_web_page_public_url(self, mock_gethostbyname, mock_get):
    """Test accessing a safe public URL."""
    url = "https://google.com"
    mock_gethostbyname.return_value = "8.8.8.8"  # Public IP

    mock_response = MagicMock()
    mock_response.status_code = 200
    # Needs to be > 3 words to pass the filter
    mock_response.content = (
        b"<html><body><p>Hello World This Is A Long Enough"
        b" Sentence</p></body></html>"
    )
    mock_get.return_value = mock_response

    result = load_web_page(url)

    # Verify it made the request
    mock_get.assert_called_once()
    self.assertIn("Hello World", result)

  @patch("requests.get")
  @patch("socket.gethostbyname")
  def test_load_web_page_private_ip(self, mock_gethostbyname, mock_get):
    """Test accessing a private IP (should be blocked)."""
    url = "http://10.0.0.1"
    # We don't necessarily need gethostbyname if we parse IP directly,
    # but if we treat it as hostname, it might call it.
    # If logic parses IP, it might skip DNS.
    # But for this test, let's assume valid DNS resolution to private IP if applicable.
    mock_gethostbyname.return_value = "10.0.0.1"

    result = load_web_page(url)

    # Should NOT make the request
    mock_get.assert_not_called()
    self.assertIn("Failed", result)

  @patch("requests.get")
  @patch("socket.gethostbyname")
  def test_load_web_page_localhost(self, mock_gethostbyname, mock_get):
    """Test accessing localhost (should be blocked)."""
    url = "http://localhost"
    mock_gethostbyname.return_value = "127.0.0.1"

    result = load_web_page(url)

    # Should NOT make the request
    mock_get.assert_not_called()
    self.assertIn("Failed", result)

  @patch("requests.get")
  @patch("socket.gethostbyname")
  def test_load_web_page_metadata_service(self, mock_gethostbyname, mock_get):
    """Test accessing metadata service (should be blocked)."""
    url = "http://169.254.169.254"
    mock_gethostbyname.return_value = "169.254.169.254"

    result = load_web_page(url)

    # Should NOT make the request
    mock_get.assert_not_called()
    self.assertIn("Failed", result)

  @patch("requests.get")
  def test_load_web_page_bad_scheme(self, mock_get):
    """Test accessing file scheme (should be blocked)."""
    url = "file:///etc/passwd"

    result = load_web_page(url)

    # Should NOT make the request
    mock_get.assert_not_called()
    self.assertIn("Failed", result)
