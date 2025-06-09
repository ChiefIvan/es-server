from bleach.sanitizer import Cleaner


class Sanitize:
    def __init__(self, entries, allowed_fields=None):
        """
        Initialize sanitizer with input data and optional fields to check.
        
        :param entries: Dictionary of input data
        :param allowed_fields: List of field names to sanitize (default: all)
        """
        
        self.entries = entries
        self.cleaner = Cleaner(tags=[], attributes={}, strip=True)
        self.server_response = "Invalid Character Found"
        self.allowed_fields = allowed_fields

    def clean(self):
        """
        Check all values (or specified fields) for invalid characters.
        Returns None if clean, or an error dict if invalid.
        """

        fields_to_check = (
            self.entries.keys() if self.allowed_fields is None 
            else self.allowed_fields
        )

        for key in fields_to_check:
            if key not in self.entries:
                continue
            
            value = self.entries[key]
            str_value = str(value) if value is not None else ""
            cleaned_value = self.cleaner.clean(str_value)

            if cleaned_value != str_value:
                return {
                    "msg": f"{self.server_response} in the field '{key.replace('psw', 'password').capitalize()}'",
                    "field": key
                }

        return None
