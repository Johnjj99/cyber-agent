# ontology.py
class Ontology:
    def __init__(self, path=None):
        self.path = path
        self.field_defs = {}
        self.relationships = []

    def get_normalizers(self, field_name):
        return []

    def get_allowed_values(self, field_name):
        return []

    def get_type(self, field_name):
        return "string"

    def get_pattern(self, field_name):
        return None

    def get_relationship(self, field_name):
        return None

    def is_field_derived(self, field_name):
        return False