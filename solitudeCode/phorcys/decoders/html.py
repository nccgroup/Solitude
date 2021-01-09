import html
from typing import Optional

from bs4 import BeautifulSoup

from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin


class Html(DecoderPlugin):
    def __call__(self, parent: Layer, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        self.layer = parent
        self._decode(data)
        return self.layer

    def _decode(self, data):
        try:
            if bool(BeautifulSoup(data, "html.parser").find()) and self.layer.parent is None:
                self.layer.human_readable = True
                self.layer.headers = [{'length': len(data)}]
                if type(data) is bytes:
                    data = data.decode()
                self.layer.lines = html.escape(data).splitlines()
                self.layer.name = "html"
            else:
                raise ValueError("[Phorcys] Failed to parse input. Not HTML")
        except:
            raise ValueError("[Phorcys] Failed to parse input. Not HTML")
