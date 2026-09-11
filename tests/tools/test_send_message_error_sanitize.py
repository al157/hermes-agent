"""Invariant tests for tools/send_message_senders._sanitize_error_text.

Behaviour contract: redacting one URL query secret must not delete its sibling
parameters, while the secret itself is still redacted; innocent text passes
through byte-identical.
"""
from tools.send_message_senders import _sanitize_error_text as fn


def test_redacting_url_secret_keeps_sibling_params():
    for param, secret in (('api_key', 'abcdef123456'),
                          ('access_token', 'abc123'),
                          ('signature', 'feedface99')):
        url = f'https://x/api?{param}={secret}&other=1'
        out = fn(url)
        assert secret not in out, f'{param} value leaked: {out!r}'
        assert '&other=1' in out, f'sibling param destroyed by {param}: {out!r}'


def test_innocent_text_untouched():
    for text in ('https://example.com/page?other=1&foo=bar',
                 'the request failed with a timeout'):
        assert fn(text) == text, f'mutated: {fn(text)!r}'
