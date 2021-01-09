import base64
from typing import Optional
from mitmproxy import ctx
from solitudeCode.phorcys.decoders.base import Layer, split_string
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin
from colorama import Fore
import uuid
import hashlib


import binascii

from .searchBase64 import searchBase64

import linecache
import os




class Base64(DecoderPlugin):
    def __call__(self, parent: Layer, headers, **metadata) -> Optional[Layer]:
        data = parent.raw_data
        self.layer = parent
        self._decode(data)
        self.layer.name = "base64"
        return self.layer

    def _decode(self, data):
        search = searchBase64()
        decodedStrings = []
        converted = []
        try:
            if type(data) is not str:
                data = str(data)

        except ValueError as err:
            ctx.log.info(Fore.RED + "convert to string base64 error" + str(err))
        # # These checks are done to ensure that we don't just decode the entire body the first time and not search
        # for any matches in the non decoded body. By adding a GUID to the first request we can then create a URL
        # decoded layer with the initial layer which can then recursively get decoded so we don't just base64 regex
        # and remove the rest of the request the first run.

        try:
            #ctx.log.info(Fore.GREEN + str(data))
            if "3db09e67-f6a3-4c86-8b20-bdac1d9cd86c" not in data:
                rootData = data + "3db09e67-f6a3-4c86-8b20-bdac1d9cd86c"
                converted.append(rootData)
            # the second round the new data will have the GUID and the previous data will not so we get an error when
            # trying to pull the GUID from the previous data
            elif "3db09e67-f6a3-4c86-8b20-bdac1d9cd86c" in data:
                previousData = str(self.layer.parent.raw_data)
                index = data.find('3db09e67-f6a3-4c86-8b20-bdac1d9cd86c')
                previousLayerIndex = previousData.find('3db09e67-f6a3-4c86-8b20-bdac1d9cd86c')
                if previousLayerIndex == -1:
                    if previousData == data:
                        data = data[:index]
                # argument should be integer or bytes-like object, not 'str'
                previousDecoded = previousData[:previousLayerIndex]
                Currentdata = data[:index]
                if Currentdata == previousDecoded:
                    data = data[:index]
                else:
                    data = data
        except ValueError as err:
            pass


        try:
        # so if an empty list is passed it it's going to be a string '[]' so we can just say less than three because
        # that's not b64 anyway
            if len(data) <= 3:
                raise ValueError("[Phorcys] base64 nothing to decode")

            base64MatchStrings = search.findbase64(data)

            for string in base64MatchStrings:
                if len(string) > 3:
                    if len(string) % 4 != 0:
                        padding = 4 - len(string) % 4
                        string += padding * "="
                    try:
                        decoded = base64.urlsafe_b64decode(string)
                        decodedStrings.append(decoded)
                    except binascii.Error as err:
                        pass


            for string in decodedStrings:
                if search.convertToASCII(string):
                    converted.append(string)

            if len(converted) == 0:
                raise ValueError("[Phorcys] base64 nothing to decode")


            child = Layer()
            child.raw_data = str(converted)
            child.parent = self.layer
            self.layer.add_extracted_layer(child)
            self.layer.human_readable = False
            self.layer.headers = [{'length': len(converted)}]
            self.layer.lines = str(converted)


        except:
            raise ValueError("[Phorcys] Failed to parse input. Not BASE64")

