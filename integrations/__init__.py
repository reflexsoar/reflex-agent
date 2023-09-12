"""
Import and create a dictionary of classes that inherit from the Output class in 
any subfolder of the integrations folder
"""
import os
import sys
import inspect
import importlib

from module.base.output import Output
from module.base.input import Input

# Create a dictionary of all the output classes
LOADED_OUTPUTS = {}
LOADED_INPUTS = {}

# Get the path to the current file
path = os.path.dirname(os.path.abspath(__file__))
# Get a list of all the files in the current directory
files = os.listdir(path)

# Loop through all the files in the current directory
for f in files:

    # Skip the current file
    if f == '__init__.py':
        continue

    # Get the name of the file without the extension
    module_name = os.path.splitext(f)[0]

    # Import the module
    module = importlib.import_module(f'integrations.{module_name}')

    # Get a list of all the classes in the module
    classes = inspect.getmembers(module, inspect.isclass)

    # Loop through all the classes in the module
    for c in classes:

        # Get the name of the class
        class_name = c[0]

        # Get the class object
        class_obj = c[1]

        # Product ID
        product_id = getattr(class_obj, 'product_identifier', None)

        # Action name
        action_name = getattr(class_obj, 'action_name', None)

        # Check if the class inherits from the Output class
        if issubclass(class_obj, Output):

            # Add the class to the outputs dictionary
            if product_id not in LOADED_OUTPUTS:
                LOADED_OUTPUTS[product_id] = {}
            
            if action_name not in LOADED_OUTPUTS[product_id]:
                LOADED_OUTPUTS[product_id][action_name] = class_obj

        if issubclass(class_obj, Input):

            # Add the class to the outputs dictionary
            if product_id not in LOADED_INPUTS:
                LOADED_INPUTS[product_id] = {}
            
            if action_name not in LOADED_INPUTS[product_id]:
                LOADED_INPUTS[product_id][action_name] = class_obj

# Add the outputs dictionary to the global variables
__all__ = [
    'LOADED_OUTPUTS',
    'LOADED_INPUTS'
]
