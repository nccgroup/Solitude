import lzma
from typing import Optional

from solitudeCode.phorcys.decoders import utils
from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin


class Lzma(DecoderPlugin):
    def __call__(self, parent: Layer, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        self.layer = parent
        self._decode(data)
        self.layer.name = "lzma"
        return self.layer

    def _decode(self, data):
        try:
            unzipped = lzma.decompress(data)
            child = Layer()
            child.raw_data = unzipped
            child.parent = self.layer
            self.layer.add_extracted_layer(child)
            self.layer.headers = [{'length': len(unzipped)}]
            self.layer.lines = utils.to_hex_lines(unzipped)
        except:
            raise ValueError("[Phorcys] Failed to parse input. Not lzma")
