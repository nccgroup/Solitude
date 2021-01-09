from typing import Optional
from urllib.parse import unquote
from mitmproxy.net.http import url
import uuid
from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin
from mitmproxy import ctx
from colorama import Fore


class UrlEncoded(DecoderPlugin):
    def __call__(self, parent: Layer, headers, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        if type(data) is not str:
            data = data.decode("ascii", "strict")
        if unquote(data) == data:
            raise ValueError("[Phorcys] URLencoder Already decoded")
        self.layer = parent
        self._decode(data, **metadata)
        self.layer.name = 'urlencoded'
        self.layer.is_structured = True
        self.layer.human_readable = True
        return self.layer

    def _decode(self, data, **metadata):
        try:
            if type(data) is not str:
                data = data.decode("ascii", "strict")


            data = unquote(data)

            if not data:
                raise ValueError("[Phorcys] URLEncoded Failed to parse input.")

            else:
                child = Layer(True)
                child.human_readable = True
                child.parent = self.layer
                child.raw_data = data
                child.name = 'UrlData'
                child.lines = []
                self.layer.lines.append(data)
                self.layer.add_extracted_layer(child)
        except AttributeError as err:
            raise AttributeError("[Phorcys] Failed to parse input")

