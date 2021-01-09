import urllib

from colorama import Fore
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.tcp import TCPFlow

from solitudeCode.database import Database
from solitudeCode.decoder import SolitudeDecoder
from solitudeCode.rules import createYaraRules
from solitudeCode.utils import utils

import os


class Solitude:

    def load(self, entry):
        global database
        database = Database()
        ctx.log.info("Solitude Loaded")
    def tcp_message(self, flow: TCPFlow):
        if flow.messages[-1]:
            ctx.log.info(Fore.CYAN + str(flow.messages[-1]))

    def websocket_message(self, flow):
        message = flow.messages[-1]
        if message.from_client:
            matching_rules = {}
            message = message.content
            ctx.log.info(Fore.LIGHTWHITE_EX + "WebSocket " + Fore.LIGHTBLUE_EX + str(message))

            solitude_decoder = SolitudeDecoder()
            phorcys_Results = solitude_decoder.decode(flow)

            connection = Database.getWebSocketConnection(database, flow)
            database.log_connection(connection)

            if phorcys_Results is not None:
                for k, v in phorcys_Results.items():
                    matching_rules[k] = v

            if matching_rules.__len__() > 0:
                database.log_webSocket_violation(matching_rules, connection, flow, phorcys_Results)

    def running(self):
        ctx.log.info("Solitude is Running!")
        createYaraRules()

    def urlDecodeList(self, req_attribute_list: list):
        ctx.log.info("urlDecodeList!")
        decode_list = []
        for chars in req_attribute_list:
            decode_list.append(urllib.parse.unquote(chars))
        return decode_list

    def cleanUpHeaders(self, flow):
        ctx.log.info("cleanUpHeaders!")
        keys = []
        values = []
        for key in flow.request.headers:
            keys.append(key)
            for value in self.urlDecodeList(flow.request.headers.get_all(key)):
                values.append(value)
        return dict(zip(keys, values))

    def error(self, flow: http.HTTPFlow):
        ctx.log.info("error!")
        utility = utils(flow)
        utility.log(err=flow.error)

    def request(self, flow: http.HTTPFlow):
        # This is the empty string which eventually contain the request body of each request (headers, body etc) when we
        # want to print it to the terminal
        request_body = ""

        matching_rules = {}

        flow.request.decode(strict=True)


        solitude_decoder = SolitudeDecoder()

        # Creates our utils object which has a lot of useful features, logging, rule matching etc... Found in utils.py
        utility = utils(flow)

        connection = Database.getConnection(database, flow)
        database.log_connection(connection)

        phorcys_Results = solitude_decoder.decode(flow)
        if phorcys_Results is not None:
            for k, v in phorcys_Results.items():
                matching_rules[k] = v

        if matching_rules.__len__() > 0:
            database.log_violation(matching_rules, connection, flow, solitude_decoder.rflow)

        utility.crossCheckFindingResults(matching_rules)


addons = [
    Solitude()
]
