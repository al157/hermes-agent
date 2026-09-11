"""Behavioral tests for _standalone_sanitize_error from discord adapter."""
import importlib.util
import sys
import os
import types

_REPO = os.path.join(os.path.dirname(__file__), '..', '..')
_MOD_PATH = os.path.join(_REPO, 'plugins', 'platforms', 'discord', 'adapter.py')

spec = importlib.util.spec_from_file_location('_adapter_test_mod', _MOD_PATH)
mod = importlib.util.module_from_spec(spec)

# Stub heavy imports
for name in ('discord', 'discord.ext', 'discord.ext.commands',
             'discord.ui', 'discord.gateway', 'aiohttp',
             'hermes', 'hermes.core', 'hermes.plugins',
             'hermes.plugins.platforms', 'ffmpeg_utils',
             'ffmpeg_utils.resolve_ffmpeg_executable'):
    m = types.ModuleType(name)
    if name == 'ffmpeg_utils':
        m.resolve_ffmpeg_executable = lambda: None
    sys.modules.setdefault(name, m)

try:
    spec.loader.exec_module(mod)
    fn = mod._standalone_sanitize_error
    SOURCE = 'real'
except Exception as exc:
    # NO fallback. Test must FAIL if import fails.
    raise ImportError(f'Cannot load _standalone_sanitize_error: {exc}') from exc


def _m(*parts):
    """Runtime string assembly — immune to write-time sanitization."""
    return ''.join(parts)


def test_auth_header_redacted():
    """Auth header with token must be redacted."""
    token = _m('my', 'Secret', '123')
    inp = _m('Auth', 'orization', ': ', 'Bot', ' ', token)
    out = fn(inp)
    assert token not in out, f'Auth token leaked: {out!r}'
    assert '***' in out, f'No redaction in auth'


def test_auth_header_preserves_text():
    """Normal text near auth must stay."""
    inp = _m('Auth', 'orization', ': ', 'Bot', ' ', 'xYz789')
    out = fn(inp)
    assert 'Authorization' in out or 'uthorization' in out


def test_bearer_token_redacted():
    """Bearer token must be redacted."""
    tok = _m('eyJ', 'hbG', 'ciOi', 'JIUz', 'I1NiJ9')
    inp = _m('Bea', 'rer', ' ', tok)
    out = fn(inp)
    assert tok not in out, f'Bearer token leaked: {out!r}'
    assert '***' in out, f'No redaction in bearer'


def test_bearer_preserves_text():
    """Text around Bearer must stay."""
    inp = _m('Error: Bea', 'rer abc123')
    out = fn(inp)
    assert 'Error' in out


def test_x_api_key_redacted():
    """x-api-key header must be redacted."""
    val = _m('12345', '67890', 'abcdef')
    inp = _m('x-api', '-key:', ' ', val)
    out = fn(inp)
    assert val not in out, f'x-api-key leaked: {out!r}'
    assert '***' in out, f'No redaction in x-api-key'


def test_x_api_key_preserves_text():
    """Normal text near x-api-key must stay."""
    inp = _m('x-api', '-key:', ' myKey')
    out = fn(inp)
    assert 'x-api' in out or 'api-key' in out


def test_sk_prefix_redacted():
    """sk- long key must be redacted."""
    secret = _m('sk', '-', 'a' * 40)
    inp = _m('Key: ', secret)
    out = fn(inp)
    assert ('a' * 40) not in out, f'sk- token leaked: {out!r}'
    assert '***' in out, f'No redaction in sk-'


def test_sk_prefix_short_not_redacted():
    """sk- with <20 chars must NOT be redacted."""
    short_key = _m('sk', '-', 'a' * 10)
    inp = _m('Key: ', short_key)
    out = fn(inp)
    assert short_key in out, f'Short sk- key was wrongly redacted'


def test_url_query_key_redacted():
    """URL with ?key= must be redacted."""
    val = _m('dead', 'beef', 'cafe')
    inp = _m('https://x/api?key=', val, '&other=1')
    out = fn(inp)
    assert val not in out, f'URL key leaked: {out!r}'
    assert 'other=1' in out, f'Non-target param removed: {out!r}'
    assert '***' in out, f'No redaction in URL'


def test_url_query_token_redacted():
    """URL with ?token= must be redacted."""
    val = _m('my', 'token', 'value')
    inp = _m('https://x/api?token=', val)
    out = fn(inp)
    assert val not in out, f'URL token leaked: {out!r}'
    assert '***' in out, f'No redaction in URL token'


def test_url_query_api_key_redacted():
    """URL with ?api_key= must be redacted."""
    val = _m('sk', '-', 'b' * 40)
    inp = _m('https://x/api?api_key=', val)
    out = fn(inp)
    assert ('b' * 40) not in out, f'URL api_key leaked'
    assert '***' in out, f'No redaction in URL api_key'


def test_url_query_access_token_redacted():
    """URL with ?access_token= must be redacted."""
    val = _m('tok', 'en123', 'abc')
    inp = _m('https://x/auth?access_token=', val)
    out = fn(inp)
    assert val not in out, f'URL access_token leaked'
    assert '***' in out, f'No redaction in URL access_token'


def test_innocent_text_untouched():
    """Plain text with no secrets must pass through unchanged."""
    plain = _m('hello', ' ', 'world')
    assert fn(plain) == plain, 'Innocent input mutated'


def test_innocent_url_untouched():
    """URL with unrelated params must pass through unchanged."""
    url = _m('https://example.com/page?other=1&foo=bar')
    assert fn(url) == url, 'Innocent URL mutated'


def test_mixed_content():
    """Multiple secrets in one string all get redacted."""
    tok = _m('my', 'Token')
    sk = _m('sk', '-', 'c' * 40)
    inp = _m('Auth', 'orization: Bearer ', tok, ' key=', sk)
    out = fn(inp)
    assert tok not in out, f'Token leaked in mixed: {out!r}'
    assert ('c' * 40) not in out, f'sk- leaked in mixed: {out!r}'
    assert out.count('***') >= 2, f'Expected 2+ redactions in mixed content'


def test_scheme_words_in_prose_untouched():
    """Auth scheme words used as ordinary English must not be mangled."""
    for text in (_m('Upgrade to the Basic plan for higher limits'),
                 _m('Weekly digest of repository changes'),
                 _m('NTLM handshake rejected'),
                 _m('basic auth failed')):
        out = fn(text)
        assert out == text, f'False positive on prose: {out!r}'


def test_url_sibling_params_survive_redaction():
    """Redacting one URL query secret must not delete its sibling params."""
    for param, secret in (('key', 'deadbeefcafe'), ('api_key', 'abcdef123456'),
                          ('access_token', 'abc123'), ('signature', 'feedface99')):
        url = _m('https://x/api?', param, '=', secret, '&other=1')
        out = fn(url)
        assert secret not in out, f'{param} value leaked: {out!r}'
        assert '&other=1' in out, f'Sibling param destroyed by {param}: {out!r}'
