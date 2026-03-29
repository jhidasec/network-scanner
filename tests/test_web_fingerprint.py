import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import _match_header_sigs


def test_nginx_server_header():
    headers = {"server": "nginx/1.24.0"}
    assert "nginx" in _match_header_sigs(headers)


def test_apache_server_header():
    headers = {"server": "Apache/2.4.57 (Debian)"}
    assert "Apache" in _match_header_sigs(headers)


def test_php_version_extracted():
    headers = {"x-powered-by": "PHP/8.1.2"}
    result = _match_header_sigs(headers)
    assert "PHP/8.1.2" in result


def test_aspnet_header():
    headers = {"x-powered-by": "ASP.NET"}
    assert "ASP.NET" in _match_header_sigs(headers)


def test_express_header():
    headers = {"x-powered-by": "Express"}
    assert "Express.js" in _match_header_sigs(headers)


def test_drupal_via_x_drupal_cache():
    headers = {"x-drupal-cache": "HIT"}
    assert "Drupal" in _match_header_sigs(headers)


def test_php_via_session_cookie():
    headers = {"set-cookie": "PHPSESSID=abc123; path=/"}
    assert "PHP" in _match_header_sigs(headers)


def test_java_via_session_cookie():
    headers = {"set-cookie": "JSESSIONID=xyz; Path=/"}
    assert "Java" in _match_header_sigs(headers)


def test_laravel_via_cookie():
    headers = {"set-cookie": "laravel_session=encrypted; path=/"}
    assert "Laravel" in _match_header_sigs(headers)


def test_wordpress_via_link_header():
    headers = {"link": '<https://example.com/wp-json/>; rel="https://api.w.org/"'}
    assert "WordPress" in _match_header_sigs(headers)


def test_empty_headers_returns_empty_set():
    assert _match_header_sigs({}) == set()


def test_unknown_headers_ignored():
    headers = {"x-custom-header": "some-value"}
    assert _match_header_sigs(headers) == set()


if __name__ == "__main__":
    import unittest
    # Run as: python3 tests/test_web_fingerprint.py
    results = []
    for name, fn in [(k, v) for k, v in globals().items() if k.startswith("test_")]:
        try:
            fn()
            results.append(f"  PASS  {name}")
        except Exception as e:
            results.append(f"  FAIL  {name}: {e}")
    print("\n".join(results))
    failed = sum(1 for r in results if "FAIL" in r)
    print(f"\n{len(results) - failed}/{len(results)} passed")
