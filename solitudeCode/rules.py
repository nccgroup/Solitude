import json
from hashlib import sha256, sha1, md5
import os

def createYaraRules():
    completedRules = []
    if os.getenv('ENVIRONMENT') == "local":
        json_path = "configs/myrules.json"
        yara_path = "configs/myrules.yara"

    if os.getenv('ENVIRONMENT') == "container-prod" or os.getenv('ENVIRONMENT') == "container-dev":
        json_path = "/mnt/configs/myrules.json"
        yara_path = "/mnt/configs/myrules.yara"

    with open(json_path) as f:
        rulefile = json.load(f)
    for k, v in rulefile.items():
        if type(v) == int:
            v = str(v)
        if ' ' in v:
            completedRules.append((
                # if no spaces then do not create rule. Also add name so there is no duplicate rule
                f'rule {k.replace(" ", "")}nospace {{ meta: {k.replace(" ", "")}AlertText = \"{k} *** \" strings: ${k.replace(" ", "")}=\"{"".join(v.split())}\" nocase condition:${k.replace(" ", "")} }}'))
            completedRules.append((
                f'rule {k.replace(" ", "")} {{ meta: {k.replace(" ", "")}AlertText = \"{k} *** \" strings: ${k.replace(" ", "")}=\"{v}\" nocase condition:${k.replace(" ", "")} }}'))
        else:
            completedRules.append((
                f'rule {k.replace(" ", "")} {{ meta: {k.replace(" ", "")}AlertText = \"{k} *** \" strings: ${k.replace(" ", "")}=\"{v}\" nocase condition:${k.replace(" ", "")} }}'))
            completedRules.append((
                f'rule {k.replace(" ", "")}sha1 {{ meta: {k.replace(" ", "")}AlertText = \"{k}*** hashed with sha1 \" strings: ${k.replace(" ", "")}=\"{sha1(bytes(v.encode())).hexdigest()}\" nocase condition:${k.replace(" ", "")} }}'))
            completedRules.append((
                f'rule {k.replace(" ", "")}sha256 {{ meta: {k.replace(" ", "")}AlertText = \"{k} *** hashed with sha256 \" strings: ${k.replace(" ", "")}=\"{sha256(bytes(v.encode())).hexdigest()}\" nocase condition:${k.replace(" ", "")} }}'))
            completedRules.append((
                f'rule {k.replace(" ", "")}md5 {{ meta: {k.replace(" ", "")}AlertText = \"{k} *** hashed with md5 \" strings: ${k.replace(" ", "")}=\"{md5(bytes(v.encode())).hexdigest()}\" nocase condition:${k.replace(" ", "")} }}'))
    f = open(yara_path, "w")
    for rule in completedRules:
        f.write("%s\n" % rule)
    f.close


class rules:
    def init(self):
        pass
