from http.cookies import SimpleCookie

def cookie_parser(raw_data):
    cookie = SimpleCookie()
    cookie.load(raw_data)

    cookies = {}
    for key, morsel in cookie.items():
        cookies[key] = morsel.value
    
    return cookies