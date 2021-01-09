from typing import Optional

from mitmproxy.contentviews.json import *

from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin


class Json(DecoderPlugin):
    def __call__(self, parent: Layer, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        self.layer = parent
        self._decode(data)
        self.layer.name = 'json'
        self.layer.is_structured = True
        self.layer.human_readable = True
        return self.layer

    def _decode(self, data, **metadata):
        try:
            content = data
            obj = {}
            if type(data) is not str:
                content = data.decode()
            if not content.strip().startswith('[') and not content.strip().startswith('{'):
                raise ValueError("[Phorcys] Failed to parse input.")
            obj['data'] = json.loads(content)
            content = json.dumps(obj, indent = 2)
            self._decode_data(obj)
            self.layer.lines = content.splitlines()
        except Exception as e:
            raise ValueError("[Phorcys] Failed to parse input.")

    def _decode_data(self, obj):
        from flatten_json import flatten
        flat = flatten(obj, ';')
        for key in flat:
            child = Layer(True)
            child.parent = self.layer
            child.raw_data = flat[key]
            child.lines = [child.raw_data]
            self.layer.add_extracted_layer(child)
