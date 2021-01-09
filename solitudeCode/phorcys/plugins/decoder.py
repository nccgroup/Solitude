from typing import Optional

from yapsy.IPlugin import IPlugin

from solitudeCode.phorcys.decoders.base import Layer


class DecoderPlugin(IPlugin):
    @staticmethod
    def filter():
        return {
            "Decoder": DecoderPlugin,
        }

    @staticmethod
    def category():
        return "Decoder"

    def __call__(self, parent: Layer, **metadata) -> Optional[Layer]:
        raise NotImplemented()
