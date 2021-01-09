import gzip
from typing import Optional

from solitudeCode.phorcys.decoders import utils
from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin


class Gzip(DecoderPlugin):
    def __call__(self, parent: Layer, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        self.layer = parent
        self._decode(data)
        self.layer.name = "gzip"
        return self.layer

    def _decode(self, data):
        if b'\x1F\x8B' not in data[:2]:
            raise ValueError("[Phorcys] Failed to parse input. Not GZIP")

        try:
            unzipped = gzip.decompress(data)
            child = Layer()
            child.raw_data = unzipped
            child.parent = self.layer
            self.layer.add_extracted_layer(child)
            self.layer.headers = [{'length': len(unzipped)}]
            self.layer.lines = utils.to_hex_lines(unzipped)
        except:
            raise ValueError("[Phorcys] Failed to parse input. Not GZIP")
