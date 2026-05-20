import unittest
from unittest.mock import patch, MagicMock
from google.adk.tools.load_web_page import load_web_page


class TestLoadWebPage(unittest.TestCase):

  @patch('google.adk.tools.load_web_page.requests.get')
  @patch('bs4.BeautifulSoup')
  def test_load_web_page_timeout_and_parser(self, mock_bs, mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b'<html><body><p>Test content</p></body></html>'
    mock_get.return_value = mock_response

    # Mock soup instance
    mock_soup = MagicMock()
    mock_soup.get_text.return_value = 'Test content'
    mock_bs.return_value = mock_soup

    url = 'http://example.com'
    load_web_page(url)

    # Verify that timeout was passed
    kwargs = mock_get.call_args.kwargs
    self.assertIn('timeout', kwargs, 'Timeout not set for requests.get')
    self.assertEqual(kwargs['timeout'], 30, 'Timeout should be 30 seconds')

    # Verify that html.parser is used
    mock_bs.assert_called_with(mock_response.content, 'html.parser')
