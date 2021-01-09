from typing import Optional

import tinycss

from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin


class Css(DecoderPlugin):
    def __call__(self, parent: Layer, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        self.layer = parent
        self._decode(data)
        return self.layer

    def _decode(self, data):
        try:
            if self.layer.parent is None:
                if type(data) is str:
                    data = data.encode()
                parser = tinycss.make_parser('page3')
                stylesheet = parser.parse_stylesheet_bytes(data)
                self.layer.human_readable = True
                self.layer.headers = [{'length': len(data), 'errors': len(stylesheet.errors)}]
                self.layer.lines = data.decode().splitlines()
                self.layer.name = "css"
            else:
                raise ValueError("[Phorcys] Failed to parse input. Not CSS")
        except Exception as e:
            raise ValueError("[Phorcys] Failed to parse input. Not CSS")
