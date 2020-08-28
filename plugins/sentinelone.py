def headers(self):
    ''' Returns the HTTP headers required for making the API call '''
    return {
            "Authorization": "ApiToken {}".format(self.config['api_key']),
            "Content-Type": "application/json"
        }

def say_hello(s):
    print(s)

def setup(app):
    app.register_action('hello', say_hello)