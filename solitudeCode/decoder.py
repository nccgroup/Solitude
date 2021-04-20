import json

from colorama import Fore
from mitmproxy import ctx
from mitmproxy.websocket import WebSocketFlow

from solitudeCode.phorcys.inspectors.dump_inspector import DumpInspector
from solitudeCode.phorcys.inspectors.yara_inspector import YaraInspector
from solitudeCode.phorcys.loaders import flow as pflow
from solitudeCode.utils import utils

import os


class SolitudeDecoder:
    rflow = ''

    def decode(self, flow):
        if os.getenv('ENVIRONMENT') == "local":
            path = "configs/"

        if os.getenv('ENVIRONMENT') == "container-prod" or os.getenv('ENVIRONMENT') == "container-dev":
            path = "/mnt/configs/"



        inspectors = [
            YaraInspector(open(path+'deviceData.yara', 'r').read()),
            YaraInspector(open(path+'gpsData.yara', 'r').read()),
            YaraInspector(open(path+'myrules.yara', 'r').read())
        ]

        if isinstance(flow, WebSocketFlow):
            di = DumpInspector(flow, inspectors)
            results = di.inspect_flow(flow)
            inspection_results = results.get('inspection')
            utility = utils(flow)
            utility.log()
            phorcys_Results = utility.returnContentResults(inspection_results)
            ctx.log.info(
                Fore.LIGHTRED_EX + "These are the results from running Phrocys with a WebSocket Message " + Fore.LIGHTYELLOW_EX + str(
                    inspection_results))

            return phorcys_Results
        else:
            rflow = pflow.convert(flow)

            # Creates our utils object which has a lot of useful features, logging, rule matching etc... Found in utils.py
            utility = utils(flow)

            # Begin our logging
            utility.log()
            di = DumpInspector(rflow, inspectors)
            # ctx.log.info(Fore.LIGHTRED_EX + str(rflow))
            di.inspect_flow(rflow)
            inspection_results = rflow.get('inspection')
            ctx.log.info(
                Fore.LIGHTRED_EX + "These are the results from running Phrocys with a flow object " + Fore.LIGHTYELLOW_EX
                + json.dumps(rflow, indent=2, sort_keys=True))
            self.rflow = rflow


            #####Inspection Results###### Flow object with Phorcys and Yara ######

            phorcys_Results = utility.returnContentResults(inspection_results)
            return phorcys_Results
