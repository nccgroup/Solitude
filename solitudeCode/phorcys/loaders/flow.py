import base64
import json
import uuid
from datetime import datetime
from datetime import timezone
from mitmproxy.net.http.http1.assemble import assemble_request, assemble_body
from urllib.parse import unquote
from mitmproxy import io
from mitmproxy.net.http import cookies
from mitmproxy import ctx

from solitudeCode.phorcys.loaders import DumpLoader


# SERVERS_SEEN = set()


# from har_dump.py script of mitmproxy
def convert(flow):
    """
       Called when a server response has been received.
    """

    # -1 indicates that these values do not apply to current request
    # ssl_time = -1
    # connect_time = -1 # ssl_time = -1
    # connect_time = -1

    # if flow.server_conn and flow.server_conn not in SERVERS_SEEN and flow.server_conn != None:
    #     connect_time = (flow.server_conn.timestamp_tcp_setup -
    #                     flow.server_conn.timestamp_start)
    #
    #     if flow.server_conn.timestamp_tls_setup is not None:
    #         ssl_time = (flow.server_conn.timestamp_tls_setup -
    #                     flow.server_conn.timestamp_tcp_setup)
    #
    #     SERVERS_SEEN.add(flow.server_conn)

    # Calculate raw timings from timestamps. DNS timings can not be calculated
    # for lack of a way to measure it. The same goes for HAR blocked.
    # mitmproxy will open a server connection as soon as it receives the host
    # and port from the client connection. So, the time spent waiting is actually
    # spent waiting between request.timestamp_end and response.timestamp_start
    # thus it correlates to HAR wait instead.
    #   #  timings_raw = {
    #         'send': flow.request.timestamp_end - flow.request.timestamp_start,
    #     #    'receive': flow.response.timestamp_end - flow.response.timestamp_start,
    #         'wait': flow.response.timestamp_start - flow.request.timestamp_end,
    #         'connect': connect_time,
    #         'ssl': ssl_time,
    #     }

    # HAR timings are integers in ms, so we re-encode the raw timings to that format.
    # timings = dict([(k, int(1000 * v)) for k, v in timings_raw.items()])

    # full_time is the sum of all timings.
    # Timings set to -1 will be ignored as per spec.
    # full_time = sum(v for v in timings.values() if v > -1)

    started_date_time = datetime.fromtimestamp(flow.request.timestamp_start, timezone.utc).isoformat()

    # Response body size and encoding
    # response_body_size = len(flow.response.raw_content)
    # response_body_decoded_size = len(flow.response.content)
    # response_body_compression = response_body_decoded_size - response_body_size

    entry = {
        "startedDateTime": started_date_time,
        "time": "none",
        "id": str(uuid.uuid4()),
        "request": {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "httpVersion": flow.request.http_version,
            "host": flow.request.pretty_host,
            "cookies": format_request_cookies(flow.request.cookies.fields),
            "headers": name_value(flow.request.headers),
            "queryString": name_value(flow.request.query or {}),
            "headersSize": len(str(flow.request.headers)),
            "bodySize": len(flow.request.content),
        },
        # "response": {
        #     "status": flow.response.status_code,
        #     "statusText": flow.response.reason,
        #     "httpVersion": flow.response.http_version,
        #     "cookies": format_response_cookies(flow.response.cookies.fields),
        #     "headers": name_value(flow.response.headers),
        #     "content": {
        #         "size": response_body_size,
        #         "compression": response_body_compression,
        #         "mimeType": flow.response.headers.get('Content-Type', '')
        #     },
        #     "redirectURL": flow.response.headers.get('Location', ''),
        #     "headersSize": len(str(flow.response.headers)),
        #     "bodySize": response_body_size,
        # },
        "cache": {},
        "timings": "null",
    }

    # Store binary data as base64
    entry["request"]["content"] = ''
    # if type(flow.response.content) == str:
    #     entry["response"]["content"] = base64.b64encode(flow.response.content.encode()).decode()
    # else:
    #     entry["response"]["content"] = base64.b64encode(flow.response.content).decode()

    if flow.request.method in ["POST", "PUT", "PATCH"]:
        params = [
            {"name": a, "value": b}
            for a, b in flow.request.urlencoded_form.items(multi=True)
        ]
        entry["request"]["postData"] = {
            "mimeType": flow.request.headers.get("Content-Type", ""),
            "params": params
        }
        if type(flow.request.content) == str:
            entry["request"]["content"] = base64.b64encode(flow.request.raw_content.encode()).decode()
        else:
            entry["request"]["content"] = base64.b64encode(flow.request.content).decode()
            # entry["request"]["content"] = base64.b64encode(flow.request.content).decode()

    if flow.server_conn.connected():
        entry["serverIPAddress"] = str(flow.server_conn.ip_address[0])
    # ctx.log.info(str(entry))
    return entry


def format_cookies(cookie_list):
    rv = []

    for name, value, attrs in cookie_list:
        cookie_har = {
            "name": name,
            "value": value,
        }

        # HAR only needs some attributes
        for key in ["path", "domain", "comment"]:
            if key in attrs:
                cookie_har[key] = attrs[key]

        # These keys need to be boolean!
        for key in ["httpOnly", "secure"]:
            cookie_har[key] = bool(key in attrs)

        # Expiration time needs to be formatted
        expire_ts = cookies.get_expiration_ts(attrs)
        if expire_ts is not None:
            cookie_har["expires"] = datetime.fromtimestamp(expire_ts, timezone.utc).isoformat()

        rv.append(cookie_har)

    return rv


def format_request_cookies(fields):
    return format_cookies(cookies.group_cookies(fields))


def format_response_cookies(fields):
    return format_cookies((c[0], c[1][0], c[1][1]) for c in fields)


def name_value(obj):
    """
        Convert (key, value) pairs to HAR format.
    """
    return [{"name": k, "value": v} for k, v in obj.items()]


class FlowLoader(DumpLoader):
    def __init__(self, flow_file):
        super(FlowLoader, self).__init__(flow_file)
        self.flows = []

    def load(self):
        # with open(self.dump_file, "rb") as dump:
        reader = io.FlowReader(self.dump_file)
        # for flow in reader.stream():
        try:
            converted = convert(reader)
            self.flows.append(converted)
        except:
            pass

    def json(self, indent=0):
        return json.dumps(self.flows, indent=indent)

    def __iter__(self):
        return iter(self.flows)

    def __len__(self):
        return len(self.flows)
