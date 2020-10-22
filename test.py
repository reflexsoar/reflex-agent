message = {
    'signal': {
        'rule': {
            'title': "AMAZING"
        }
    }
}

def get_nested_field(message, field):
    '''
    Iterates over nested fields to get the final desired value
    e.g signal.rule.name should return the value of name
    '''

    if isinstance(field, str):
        args = field.split('.')
    else:
        args = field
   
    if args and message:
        element = args[0]
        if element:
            value = message.get(element)
            return value if len(args) == 1 else get_nested_field(value, args[1:])


print(get_nested_field(message, 'signal.rule.title'))