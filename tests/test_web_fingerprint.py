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


def test_iis_server_header():
    headers = {"server": "Microsoft-IIS/10.0"}
    assert "IIS" in _match_header_sigs(headers)


def test_litespeed_server_header():
    headers = {"server": "LiteSpeed"}
    assert "LiteSpeed" in _match_header_sigs(headers)


def test_drupal_via_x_generator():
    headers = {"x-generator": "Drupal 10 (https://www.drupal.org)"}
    assert "Drupal" in _match_header_sigs(headers)


def test_aspnet_via_session_cookie():
    headers = {"set-cookie": "ASP.NET_SessionId=abc123; path=/"}
    assert "ASP.NET" in _match_header_sigs(headers)


from scanner import _match_body_sigs


def test_wordpress_wp_content_path():
    body = '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
    assert "WordPress" in _match_body_sigs(body)


def test_wordpress_meta_generator():
    body = '<meta name="generator" content="WordPress 6.4.2" />'
    assert "WordPress" in _match_body_sigs(body)


def test_drupal_settings():
    body = "var drupalSettings = {}; Drupal.settings = {};"
    assert "Drupal" in _match_body_sigs(body)


def test_nextjs_data_tag():
    body = '<script id="__NEXT_DATA__" type="application/json">{"page":"/","query":{}}</script>'
    assert "Next.js" in _match_body_sigs(body)


def test_react_data_root():
    body = '<div data-reactroot="" id="root"></div>'
    assert "React" in _match_body_sigs(body)


def test_angular_ng_version():
    body = '<app-root _nghost-abc ng-version="17.0.0"></app-root>'
    assert "Angular" in _match_body_sigs(body)


def test_jquery_script_tag():
    body = '<script src="/assets/jquery.min.js"></script>'
    assert "jQuery" in _match_body_sigs(body)


def test_bootstrap_link_tag():
    body = '<link rel="stylesheet" href="/css/bootstrap.min.css">'
    assert "Bootstrap" in _match_body_sigs(body)


def test_bootstrap_not_matched_in_body_text():
    # "bootstrap" in plain text (not a <link> tag) should NOT match
    body = "<p>We bootstrap our app on startup.</p>"
    assert "Bootstrap" not in _match_body_sigs(body)


def test_joomla_administrator_path():
    body = '<a href="/administrator/index.php">Admin</a>'
    assert "Joomla" in _match_body_sigs(body)


def test_empty_body_returns_empty_set():
    assert _match_body_sigs("") == set()


def test_plain_html_no_signatures():
    body = "<html><body><h1>Hello World</h1></body></html>"
    assert _match_body_sigs(body) == set()


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
