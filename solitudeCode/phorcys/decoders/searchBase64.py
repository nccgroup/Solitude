from mitmproxy import ctx
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.net.http.http1.assemble import assemble_request
from mitmproxy import flow
from mitmproxy import http
import urllib
from colorama import Fore
import base64
import binascii
import re


class searchBase64:

    def __init__(self):
        pass

    def check_ascii(self, s):
        return all(ord(c) < 128 for c in s)

    def convertToASCII(self, encodedString):

        if len(encodedString) != 0 and type(encodedString) != str:
            try:
                decoded = encodedString.decode('utf-8')
                if self.check_ascii(decoded):

                    return decoded

            except UnicodeDecodeError as err:
                return

    def findbase64(self, request_body):
        if type(request_body) != str:
            request_body = str(request_body)

        decodedStrings = []
        match = re.findall(r"[a-zA-Z0-9+/]+={,2}", request_body)


        if match:
            return match

    def base64(self, string):

        finalConvertedStrings = []
        base64MatchStrings = self.findbase64(string)


        Base64decodedStrings = []
        if type(string) != str:
            finalConvertedStrings.append(self.convertToASCII(string))



        for string in finalConvertedStrings:
            if string is not None:
                ctx.log.info(Fore.GREEN + str(string))
        for string in base64MatchStrings:
            if len(string) > 3:

                try:
                    decoded = base64.urlsafe_b64decode(string)

                    Base64decodedStrings.append(decoded)
                except binascii.Error as err:
                    ctx.log.info(Fore.MAGENTA + str(err) + str(string))
                    return

        for string in Base64decodedStrings:
            self.base64(string)