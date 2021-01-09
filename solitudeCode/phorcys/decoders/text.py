from typing import Optional

from solitudeCode.phorcys.decoders.base import Layer, split_string
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin
from mitmproxy import ctx
from colorama import Fore

class Text(DecoderPlugin):
    def __call__(self, parent: Layer, headers, **metadata) -> Optional[Layer]:

        if parent.name != 'root':
            raise ValueError("[Phorcys] Failed to parse input. Not text")

        data = parent.raw_data
        try:
            self.layer = parent
            child = Layer()
            child.raw_data = str(data)  # str(' '.join(map(str, decodedStrings)))
            child.parent = self.layer
            self.layer.name = "Base Layer"
            self.layer.add_extracted_layer(child)
            self.layer.human_readable = True
            self.layer.lines = str(data)
            return self.layer
        except ValueError as err:
            ctx.log.info(Fore.MAGENTA + str(err))
            # raise ValueError("[Phorcys] Failed to parse input. Not text")
