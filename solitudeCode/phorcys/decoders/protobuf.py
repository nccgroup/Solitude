from typing import Optional

from solitudeCode.blackboxprotobuf.lib.interface import decode_message
from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin
from mitmproxy import ctx
from colorama import Fore

class Protobuf(DecoderPlugin):
    def __call__(self, parent: Layer, headers, **metadata) -> Optional[Layer]:
        if parent.name != "root":
            raise ValueError("Already decoded root layer")

        # TODO: Add check to only decode once -- if self.layer.name == 'root' go ahead
        protoBuffDomains = ["app-measurement.com", "application/protobuf", "play.googleapis.com",
                            "application/x-protobuffer", "cloudconfig.googleapis.com", "application/x-protobuf",
                            "firebaselogging-pa.googleapis.com"]

        # for some reason sometimes the headers is a list somtimes a dict
        # we also need to make sure that the body is empty --- have seen POST and GET with protobuf headers
        try:
            # ctx.log.info(Fore.MAGENTA + str(type(headers)))
            for header in headers:
                if header in protoBuffDomains:
                    # ctx.log.info(Fore.MAGENTA + str(header))
                    pass
        except:
            ctx.log.info(Fore.RED + "[Phorcys] No protobuf Headers did not decode")
            raise ValueError("[Phorcys] No protobuf Headers did not decode")

        data = parent.raw_data

        # try:
        #     if len(parent.raw_data) == 0:
        #         ctx.log.info(Fore.RED + "Empty body can't decode Protobuf")
        # except:
        #     raise ValueError("[Protobuf] Body is empty don't have to Decode")

        self.layer = parent

        # ctx.log.info(Fore.GREEN + str(headers))
        # ctx.log.info(Fore.RED + str(type(headers)))

        # try:
        #     for header in protoBuffDomains:
        #         if header in str(headers):
        # ctx.log.info(Fore.GREEN + "Found Protobuf Domain " + str(header))
        try:
            self._decode(data)
            self.layer.name = 'protobuf'
            self.layer.is_structured = True
            self.layer.human_readable = True
            return self.layer

        except:
            raise ValueError("[Phorcys] Failed to parse input. Not protobuf")

    def _decode(self, data, **metadata):
        try:
            content = str(decode_message(data))
            # ctx.log.info(Fore.GREEN +str(lib.interface.decode_message((data))))
            # for data in decode_message(data):
            #    ctx.log.info(Fore.MAGENTA + str(data))
            #    content = str(data)

        except:
            raise ValueError(["Protobuf Could not Decode"])

        self.layer.raw_data = content
        self.layer.lines = content
        child = Layer(True)
        child.parent = self.layer
        child.raw_data = content
        child.lines = child.raw_data
        self.layer.add_extracted_layer(child)

