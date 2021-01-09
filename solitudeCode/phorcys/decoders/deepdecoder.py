import os
from os import path
from os.path import expanduser
from typing import Optional
from mitmproxy import ctx
from yapsy.PluginManager import PluginManager
from colorama import Fore
from solitudeCode.phorcys.decoders import utils
from solitudeCode.phorcys.decoders.base import Layer
from solitudeCode.phorcys.decoders.base64 import Base64
from solitudeCode.phorcys.decoders.bzip import Bzip
from solitudeCode.phorcys.decoders.css import Css
from solitudeCode.phorcys.decoders.gzip import Gzip
from solitudeCode.phorcys.decoders.html import Html
from solitudeCode.phorcys.decoders.json import Json
from solitudeCode.phorcys.decoders.lzma import Lzma
from solitudeCode.phorcys.decoders.protobuf import Protobuf
from solitudeCode.phorcys.decoders.text import Text
from solitudeCode.phorcys.decoders.urlencoded import UrlEncoded
from solitudeCode.phorcys.decoders.zlib import Zlib
from solitudeCode.phorcys.plugins.decoder import DecoderPlugin


class DeepDecoder:
    def __init__(self):
        self.top_layer = None
        self.plugin_manager = PluginManager()
        self.plugin_locations = [path.join(expanduser("~"), '.phorcysOld', 'plugins')]
        try:
            environ_locations = os.environ['PLUGINS_DIR']
            if environ_locations is not None and len(environ_locations) > 0:
                dirs = environ_locations.split(';')
                for d in dirs:
                    if os.path.isdir(d):
                        self.plugin_locations.append(d)
                    else:
                        pass
        except KeyError:
            pass
        self.plugin_manager.setPluginPlaces(directories_list = self.plugin_locations)
        self.plugin_manager.setCategoriesFilter(DecoderPlugin.filter())
        self.plugin_manager.collectPlugins()

    def get_loaded_plugins(self):
        return self.plugin_manager.getPluginsOfCategory(DecoderPlugin.category())

    def _complete_leaves(self):
        for leaf in self.top_layer.leaves:
            if leaf.parent is not None:
                leaf.parent.name = 'text'
                leaf.parent.human_readable = True
                leaf.parent.raw_data = ''.join(leaf.parent.lines)
                leaf.parent.del_extracted_layer(leaf)

    def decode(self, data, headers, **kwargs) -> Layer:
        parent = Layer()
        parent.raw_data = data
        parent.name = 'root'

        to_visit = [parent]
        while len(to_visit) != 0:
            next = to_visit.pop()
            layer = self.go_deeper(next, headers, **kwargs)
            if layer is not None:
                layers = layer.extracted_layers
                if layers is not None:
                    to_visit.extend(layers)

        self.top_layer = parent
        #ctx.log.info(Fore.RED + str(self.top_layer.extracted_layers))
        return parent

    def inspect(self):
        pass

    def go_deeper(self, parent, headers, **xargs) -> Optional[Layer]:
        protocols = [
            Protobuf(),
            Text(),
            UrlEncoded(),
            Base64(),
            Json(),
            # Lzma(),
            # Zlib(),
            # Bzip(),
            # Gzip(),
            #  Html(),
            #   Css(),
        ]

        plugins = []
        for plugin in self.plugin_manager.getPluginsOfCategory(DecoderPlugin.category()):
            plugins.append(plugin.plugin_object)

        plugins.extend(protocols)
        protocols = plugins

        for p in protocols:
            try:
                return p(parent, headers, **xargs)
            except Exception as e:
                # Uncomment below if you want to see what the error from the decoder is
                # ctx.log.info(Fore.MAGENTA + str(e))
                # print(traceback.format_exc())
                # print('Not %s' % type(p))
                # print(e)
                pass

        return None
