import base64
from bson.objectid import ObjectId

def process_data(data):
    """
    Recursively processes a data structure to convert all ObjectId instances to strings,
    encode bytes objects to base64 strings, or remove them if specified.

    Parameters:
        data (dict or list): The data structure (dictionary or list) to process.
        remove (bool): Whether to remove ObjectId fields instead of converting them to strings.
        
    Returns:
        The processed data structure.
    """
    if isinstance(data, dict):
        # If the data is a dictionary, process each key-value pair
        processed_dict = {}
        for key, value in data.items():
            if isinstance(value, ObjectId):
                # Convert ObjectId to string
                processed_dict[key] = str(value)
            elif isinstance(value, bytes):
                # Encode bytes to base64 string
                processed_dict[key] = base64.b64encode(value).decode('utf-8')
            else:
                # Recursively process the value
                processed_dict[key] = process_data(value)
        return processed_dict
    
    elif isinstance(data, list):
        # If the data is a list, process each item
        return [process_data(item) for item in data]
    
    else:
        # Base case: return data if it's neither a dict nor a list
        return data

process_object_ids = process_data