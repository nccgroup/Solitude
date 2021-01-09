from typing import Optional

from mitmproxy.net import http

from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin


class Multipart(DecoderPlugin):
    def __call__(self, parent: Layer, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        self.layer = parent
        self._decode(data)
        self.layer.name = 'multipart'
        self.layer.is_structured = True
        self.layer.human_readable = True
        return self.layer

    def _decode(self, data, **metadata):
        try:
            data = http.multipart.decode({}, data)
            self.layer.lines = []
            for (k, v) in data:
                child = Layer(True)
                child.human_readable = True
                child.parent = self.layer
                child.raw_data = v
                child.name = k
                child.lines = [v]
                self.layer.lines.append('%s' % v)
                self.layer.add_extracted_layer(child)
        except Exception as e:
            raise ValueError("[Phorcys] Failed to parse input.")
