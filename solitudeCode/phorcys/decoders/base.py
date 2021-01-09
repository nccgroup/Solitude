import base64
import html
import json
import uuid

split_string = lambda x, n: [x[i:i + n] for i in range(0, len(x), n)]


class Layer:
    def __init__(self, is_structured = False):
        self.id = str(uuid.uuid4())
        self.is_structured = is_structured
        self.human_readable = False
        self._parent = None
        self._children = []
        self._name = ''
        self._layers = []
        self._headers = []
        self._lines = []
        self._matching_rules = []
        self._raw_data = None

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, val):
        self._parent = val

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, val: str):
        self._name = val

    @property
    def children(self) -> list:
        return self._children

    def add_child(self, val: object):
        self._children.append(val)

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, val):
        self._headers = val

    def add_header(self, val):
        self._headers.append(val)

    @property
    def lines(self):
        return self._lines

    @lines.setter
    def lines(self, val):
        self._lines = val

    def add_line(self, val):
        self._lines.append(val)

    @property
    def raw_data(self):
        return self._raw_data

    @property
    def raw_data_base64(self):
        return base64.b64encode(self._raw_data)

    @raw_data.setter
    def raw_data(self, val):
        self._raw_data = val

    @property
    def extracted_layers(self) -> list:
        return self._layers

    def add_extracted_layer(self, val):
        self._layers.append(val)

    def del_extracted_layer(self, val):
        self._layers.remove(val)

    @property
    def matching_rules(self) -> list:
        return self._matching_rules

    def add_matching_rule(self, val):
        self._matching_rules.append(val)

    def clear_extracted_layer(self):
        self._layers = []

    def _get_safe_lines(self):
        lines = []
        for l in self.lines:
            if type(l) is str:
                lines.append(html.escape(l))
            else:
                lines.append(l)
        return lines

    def dict(self, recursive = False) -> dict:
        ret = {
            'id': self.id,
            'name': self._name,
            'human_readable': self.human_readable,
            'matching_rules': self.matching_rules,
            'headers': self.headers,
            'children': [l.dict(recursive) for l in self._layers],
            'length': -1,
            'text': self.lines,
        }
        if self.raw_data is not None:
            ret['length'] = len(str(self._raw_data))

        return ret

    @property
    def leaves(self) -> list:
        to_visit = [self]
        leaves = []
        while len(to_visit) != 0:
            next = to_visit.pop()
            if len(next.extracted_layers) == 0:
                leaves.append(next)
            else:
                to_visit.extend(next.extracted_layers)

        return leaves

    def __repr__(self):
        return json.dumps(self.dict(True), indent = 2, sort_keys = True)
