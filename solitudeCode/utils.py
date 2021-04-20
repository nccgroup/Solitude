import json
import os
from datetime import datetime
from hashlib import sha256, sha1, md5

from colorama import Fore
from mitmproxy import ctx
from mitmproxy.websocket import WebSocketFlow


class utils:

    def __init__(self, flow):
        self.flow = flow

    def returnContentResults(self, inspectionDictionary):
        matchingRulesDict = {}
        if inspectionDictionary["tags"]:
            for tag in inspectionDictionary["tags"].items():
                if tag == "ipAddress":
                    ctx.log.info(Fore.LIGHTBLUE_EX + "We gotta a tag")
                if isinstance(self.flow, WebSocketFlow):
                    ctx.log.info(Fore.LIGHTGREEN_EX + tag[0] + Fore.LIGHTCYAN_EX + tag[
                        1] + Fore.LIGHTGREEN_EX + " is being sent to " + Fore.YELLOW +
                                 self.flow.handshake_flow.request.headers['host'])
                else:
                    ctx.log.info(Fore.LIGHTGREEN_EX + tag[0] + Fore.LIGHTCYAN_EX + tag[
                        1] + Fore.LIGHTGREEN_EX + " is being sent to " + Fore.YELLOW + self.flow.request.pretty_host)
                # For now we will remove Phorcys from printing out as we are not using the the standard string search code and have switched to ony using yara and the decoders
                matchingRulesDict[tag[0]] = tag[1]
                # ctx.log.info(Fore.LIGHTBLUE_EX + str(matchingRulesDict))
                self.log(str(matchingRulesDict))
        return matchingRulesDict

    def log(self, violation=None, err=None, issue=None):

        timestamp = datetime.now().strftime("%H:%M:%S")

        if violation:
            if isinstance(self.flow, WebSocketFlow):
                line = "[WARN] {} - {} - {} - {}\n".format(timestamp, "Websocket Message",
                                                           self.flow.handshake_flow.request.headers['host'], violation)
            else:
                line = "[WARN] {} - {} - {} - {}\n".format(timestamp, self.flow.request.method,
                                                           self.flow.request.pretty_url, violation)
            self.logEntry(line)
        elif err:
            line = "[ERROR] {} - {}\n".format(timestamp, err)
            self.logEntry(line)

        elif issue:
            line = "[ISSUE] {} - {}\n".format(timestamp, issue)
            self.logEntry(line)

        else:
            if isinstance(self.flow, WebSocketFlow):
                line = "[INFO] {} - {} {}\n".format(timestamp, "Websocket Message",
                                                    self.flow.handshake_flow.request.headers['host'])
            else:
                line = "[INFO] {} - {} {}\n".format(timestamp, self.flow.request.method, self.flow.request.pretty_url)

            self.logEntry(line)

    def logEntry(self, line):
        if os.getenv('ENVIRONMENT') == "local":
            path = os.getcwd()+"/logs/"

        if os.getenv('ENVIRONMENT') == "container-prod" or os.getenv('ENVIRONMENT') == "container-dev":
            path = "/mnt/logs/"

        if not os.path.exists(path):
            os.mkdir(path)

        file = path + "solitudeCode-" + str(datetime.now().strftime("%Y-%m-%d")) + ".log"

        with open(file, 'a') as f:
            f.write(line)
            f.close()

    # For now we will remove Phorcys from printing out as we are not using the the standard string search code and have switched to ony using yara and the decoders
    def crossCheckFindingResults(self, matching_rules):
        yaraJSONandRegexFindings = {}
        phorchysFindings = {}
        for data in matching_rules.items():
            if data[0].startswith('Mac Address Regex') or data[0].startswith('IP Regex') or data[0].startswith(
                    "From JSON dynamicStrings on non decoded request"):
                yaraJSONandRegexFindings[data[0]] = data[1]
            elif data[0].startswith("Phorcys"):
                phorchysFindings[data[0]] = data[1]
        for data in yaraJSONandRegexFindings.items():
            if data[1] not in phorchysFindings.values():
                self.log(
                    issue="IMPORTANT Discrepency in Phorcys vs regular search methods: Inspect why Phorcys did not "
                          "find: " +
                          data[1])
                ctx.log.info(
                    Fore.YELLOW + "IMPORTANT Discrepency in Phorcys vs regular search methods: Inspect why Phorcys "
                                  "did not find: " + Fore.LIGHTRED_EX + str(
                        data[1]))
            # if there are matches for ip,mac, or JSON then check to see if they are in the phorcys. If not,
            # we have problems. This way

    # if there is any extra data in phorcys it won't matter because we are only seeing if the data in ip,mac or JSON
    # is in phorcys. This is when phorcys finds stuff and has matches from decoded data and the regular searches do
    # not.. # However, we need to account for the fact if say Phorcys finds more decoded data # however does not find
    # other stuff. doing a data match for match here would make sense soo check to see that they find the same data
    # and if phorcys finds more than cool..

    def createYaraRules(self):
        completedRules = []
        with open('configs/myrules.json') as f:
            rulefile = json.load(f)
        for k, v in rulefile.items():
            completedRules.append((
                f'rule {k.replace(" ", "")} {{ meta: {k.replace(" ", "")}AlertText = {k} \" strings: ${k.replace(" ", "")}=\"{v}\" nocase condition:${k.replace(" ", "")} }}'))
            completedRules.append((
                f'rule {k.replace(" ", "")}sha1 {{ meta: {k.replace(" ", "")}AlertText = {k} hashed with sha1 \" strings: ${k.replace(" ", "")}=\"{sha1(bytes(v.encode())).hexdigest()}\" nocase condition:${k.replace(" ", "")} }}'))
            completedRules.append((
                f'rule {k.replace(" ", "")}sha256 {{ meta: {k.replace(" ", "")}AlertText = {k} hashed with sha256 \" strings: ${k.replace(" ", "")}=\"{sha256(bytes(v.encode())).hexdigest()}\" nocase condition:${k.replace(" ", "")} }}'))
            completedRules.append((
                f'rule {k.replace(" ", "")}md5 {{ meta: {k.replace(" ", "")}AlertText =  {k} hashed with md5\" strings: ${k.replace(" ", "")}=\"{md5(bytes(v.encode())).hexdigest()}\" nocase condition:${k.replace(" ", "")} }}'))
        f = open('configs/myrules.yara', "w")
        for rule in completedRules:
            f.write("%s\n" % rule)
        f.close
