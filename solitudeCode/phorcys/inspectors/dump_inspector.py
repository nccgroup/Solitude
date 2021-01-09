import base64
from functools import partial
from multiprocessing import Pool, Lock
from urllib.parse import unquote
from solitudeCode.phorcys.decoders.deepdecoder import DeepDecoder
from solitudeCode.phorcys.loaders import DumpLoader
from mitmproxy import ctx
from colorama import Fore
from mitmproxy.websocket import WebSocketFlow

class DumpInspector:
    def __init__(self, dump: DumpLoader, inspectors=[]):
        self.dump = dump
        self.inspectors = inspectors

    def set_inspectors(self, inspectors):
        self.inspectors = inspectors

    def inspect(self):
        with Pool() as p:
            flows = p.map(self.inspect_flow, self.dump)
            p.close()
            p.join()
            self.dump.flows = flows

    def inspect_flow(self, f):
        # for f in self.dump:
        total = 0
        all_tags = {}
        all_rules = []
        inspection_results = {}
        # Inspect URL
        dd = DeepDecoder()

        # Check to see if it's a websocket message and decode accordingly
        if isinstance(f, WebSocketFlow):
            message = f.messages[-1]
            if message.from_client:
                message = message.content
            top_layer = dd.decode(message, 'No Headers WebSocket Message')
            count = 0
            for i in self.inspectors:
                count, tags, rules = i(top_layer)
                all_rules.append(rules)
                if len(tags) != 0:
                    all_tags.update(tags)
            inspection_results['WebSocketMessage'] = {'layers': top_layer.dict(recursive=True), 'clues': count}
            total += count
        else:
            splitUrl = str(f['request']['url']).split('/')
            # We split this because it won't base64 decode any base64 encoded strings well if they are path parameters.
            top_layer = dd.decode(splitUrl, f['request']['headers'])
            count = 0
            for i in self.inspectors:
                count, tags, rules = i(top_layer)
                all_rules.append(rules)
                if len(tags) != 0:
                    all_tags.update(tags)
            inspection_results['url'] = {'layers': top_layer.dict(recursive=True), 'clues': count}
            total += count


            dd = DeepDecoder()
            top_layer = dd.decode(str(f['request']['headers']), str(f['request']['headers']))
            count = 0
            for i in self.inspectors:
                count, tags, rules = i(top_layer)
                all_rules.append(rules)
                if len(tags) != 0:
                    all_tags.update(tags)
            inspection_results['content'] = {'layers': top_layer.dict(recursive=True), 'clues': count}
            total += count

            # Inspect Request payload
            if len(f['request']['content']) > 0:
                dd = DeepDecoder()

                try:
                    content = base64.b64decode(f['request']['content']).decode('utf8')
                except UnicodeDecodeError:
                    content = base64.b64decode(f['request']['content'])
                top_layer = dd.decode(content, f['request']['headers'])
                count = 0
                for i in self.inspectors:
                    count, tags, rules = i(top_layer)
                    all_rules.append(rules)
                    if len(tags) != 0:
                        all_tags.update(tags)
                inspection_results['content'] = {'layers': top_layer.dict(recursive=True), 'clues': count}
                total += count

        aggregated_rules = {}
        for r in all_rules:
            for k, v in r.items():
                if k not in aggregated_rules:
                    aggregated_rules[k] = v
                else:
                    aggregated_rules[k]['count'] += v['count']

        if isinstance(f, WebSocketFlow):
            f = inspection_results
        f['inspection'] = inspection_results
        f['inspection']['rules'] = aggregated_rules
        f['inspection']['clues'] = total
        f['inspection']['tags'] = all_tags
        return f
