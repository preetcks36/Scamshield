def check_https(url):
    if url.startswith("https://"):
        return True
    return False


# Test URLs
test_url_1 = "https://example.com"
test_url_2 = "http://example.com"

print(test_url_1, "uses HTTPS:", check_https(test_url_1))
print(test_url_2, "uses HTTPS:", check_https(test_url_2))