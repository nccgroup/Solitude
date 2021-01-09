import yara
from urllib.parse import unquote
from solitudeCode.phorcys.decoders.base import Layer
from mitmproxy import ctx
from colorama import Fore
import base64


class YaraInspector:
    def __init__(self, rules: str):
        self.layer = None
        self.rules_src = rules

    def __call__(self, layer: Layer, *args, **kwargs):
        self.rules = yara.compile(source=self.rules_src)
        meta = []
        matchData = {}
        rules = {}
        self.layer = layer
        count = 0
        leaves = self.layer.leaves

        if len(self.layer.extracted_layers) == 0:
            return count, list(set(meta)), rules
        # extracted_layers = self.layer.extracted_layers[0]
        # ctx.log.info(Fore.GREEN + str(type(self.layer.extracted_layers)))
        lastlayer = self.layer.extracted_layers
        # [0] This is a list  ctx.log.info(Fore.GREEN + str(type(lastlayer)))
        # lastlayer[0].extracted_layers[0].raw_data

        # rootLayer = self.layer.raw_data
        # self.layer.extracted_layers[0].extracted_layers[0].extracted_layers[0]

        # decodedLayers.append(rootLayer)
        extractedLayers = [self.layer.extracted_layers[0]]
        while len(lastlayer) > 0:
            try:
                lastlayer = lastlayer[0].extracted_layers
                extractedLayers.append(lastlayer[0])
            except IndexError as err:
                break

        for l in extractedLayers:
            data = str(l.raw_data)
            if type(data) != str:
                data = str(data)
            matches = self.rules.match(data=data)
            # ctx.log.info(Fore.GREEN + str(extractedLayers))

            if len(matches) > 0:
                count += 1
                for m in matches:
                    if str(m) not in rules:
                        rules[str(m)] = {'rule': str(m), 'tags': m.meta, 'count': len(m.strings)}
                    else:
                        rules[str(m)]['count'] += len(m.strings)
                    l.add_matching_rule({'rule': str(m), 'tags': m.meta, 'count': len(m.strings)})
                    # check to see if the match data is already in the matchvalues dict to make sure there are no
                    # duplicates
                    for match in m.strings:

                        # ctx.log.info(Fore.CYAN + str(m.strings))
                        # need to figure out if we see the same key value pair not to add twice
                        # also need to figure out how to not overwrite key if the value is different
                        # if matchData[list(m.meta.values())[0]] != match[2].decode("utf-8"):
                        # if match[2].decode("utf-8") not in matchData.values():

                        if list(m.meta.values())[0] not in matchData.keys():
                            matchData.update({list(m.meta.values())[0]: match[2].decode("utf-8")})

                        # else: matchData.update({list(m.meta.values())[0] + " " + str(count) + " ": match[2].decode(
                        # "utf-8")})

                        # ctx.log.info(Fore.LIGHTBLUE_EX + matchData.get(list(m.meta.values())[0]))
                        if match[2].decode("utf-8") not in matchData.values():
                            matchData.update({list(m.meta.values())[0] + " " + "(" + str(count + 1) + ")" + " ": match[
                                2].decode("utf-8")})

        # ctx.log.info(Fore.YELLOW + str(matchData) + Fore.GREEN + str(tags))
        return count, matchData, rules
