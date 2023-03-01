class IndexedDict(dict):

    def __init__(self, *args, **kwargs):
        super().__init__()
        root_key = kwargs.pop('root_key', None)
        target_dict = self.index_data(target_dict={}, root_key=root_key, *args, **kwargs)
        self.update(target_dict)

    def index_data(self, data=None, prefix=None, keys=[], target_dict=None, root_key=None):
        """Flattens all the keys and their values in to a new dictionary
        so that the entire path is searchable using dot notation.
        Args:
            data (dict): The dictionary to flatten.
            prefix (str): The prefix to use for the flattened keys.
            keys (list): The list of keys to flatten.
            target_dict (dict): The dictionary to store the flattened keys and values.
            root_key (str): The root key to use for the flattened keys.
        Return:
            dict: The flattened dictionary.
        """
        if data is None:
            data = self

        if root_key:
            data = data[root_key]

        if isinstance(data, dict):
            for key, value in data.items():
                if prefix:
                    key = f"{prefix}.{key}"
                self.index_data(value, key, keys, target_dict)
        elif isinstance(data, list):
            for value in data:
                self.index_data(value, prefix, keys, target_dict)
        else:
            if prefix in target_dict:
                if isinstance(target_dict[prefix], list):
                    target_dict[prefix].append(data)
                else:
                    target_dict[prefix] = [target_dict[prefix], data]
            else:
                target_dict[prefix] = data
        return target_dict

    def __getitem__(self, key):
        """Returns the value of the key if it exists, otherwise returns None."""
        if key in self:
            return super().__getitem__(key)
        else:
            raise KeyError(f"Key '{key}' does not exist.")