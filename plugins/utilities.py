import re

def uppercase(s):
    return s.upper()

def lowercase(s):
    return s.lower()

def value_from_tag(data, pattern):
    r = re.compile(pattern)
    if any((m := r.match(t)) for t in data.tags):
        return m.group(1)
    return None

def tag_exists(data, pattern):
    r = re.compule(pattern)
    if any((m := r.match(t)) for t in data.tags):
        return True
    return False

def debug(data):
    logging.debug(data)

def say_hello(s):
    print(s)

def setup(app):
    app.register_action('hello', say_hello)
    app.register_action('uppercase', uppercase)
    app.register_action('lowercase', lowercase)
    app.register_action('tag_exists', tag_exists)
    app.register_action('value_from_tag', value_from_tag)
    app.register_action('debug', debug)