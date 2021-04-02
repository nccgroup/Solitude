import datetime
import json

from sqlalchemy.orm import sessionmaker

from solitudeCode.db_utils import return_engine
from solitudeCode.models.connections import Connections
from solitudeCode.models.violations import Violations


class Database:
    engine = return_engine()

    def __init__(self):
        Session = sessionmaker(bind=self.engine)
        self.db_session = Session()

    def log_connection(self, connection):
        self.db_session.add(connection)
        self.db_session.commit()

    def getConnection(self, flow):
        try:
            ip = flow.server_conn.ip_address[0]
        except TypeError:
            ip = 'null'
        content_length = ''
        content_type = ''
        user_agent = ''
        for header in flow.request.data.headers.fields:
            decoded_header = header[0].decode('utf8').casefold()
            if decoded_header == 'content-length':
                content_length = int(header[1].decode('utf8').casefold())
            if decoded_header == 'content-type':
                content_type = header[1].decode('utf8').casefold()
            if decoded_header == 'user-agent':
                user_agent = header[1].decode('utf8')
        return Connections(host=flow.request.pretty_host, url=flow.request.pretty_url,
                           time=datetime.datetime.fromtimestamp(flow.request.data.timestamp_start),
                           method=flow.request.method,
                           content_length=content_length,
                           content_type=content_type, IP_address=ip, user_agent=user_agent)

    def getWebSocketConnection(self, flow):
        try:
            ip = flow.server_conn.ip_address[0]
        except TypeError:
            ip = 'null'
        return Connections(host=flow.server_conn.address[0], url=flow.handshake_flow.request.pretty_url,
                           time=datetime.datetime.fromtimestamp(flow.messages[-1].timestamp), method='N/A',
                           content_length=len(flow.messages[-1].content), IP_address=flow.server_conn.ip_address[0],
                           content_type=None, user_agent=None)

    def log_violation(self, matching_rules, connection, flow, phorcies_object):
        cookies = ''
        for header in flow.request.data.headers.fields:
            decoded_header = header[0].decode('utf8').casefold()
            if decoded_header == 'cookie':
                cookies = header[1].decode('utf8').casefold()

        for k, v in matching_rules.items():
            self.db_session.add(
                Violations(connection_ID=connection.id, body=flow.request.raw_content,
                           phorcies_object=json.dumps(phorcies_object, sort_keys=True).encode('utf-8'),
                           violation_message="{} {}".format(k, v), cookies=cookies))

        self.db_session.commit()

    def log_webSocket_violation(self, matching_rules, connection, flow, phorcies_object):
        for k, v in matching_rules.items():
            self.db_session.add(
                Violations(connection_ID=connection.id, body=flow.messages[-1].content.encode('utf-8'),
                           phorcies_object=json.dumps(phorcies_object, sort_keys=True).encode('utf-8'),
                           violation_message="{} {}".format(k, v), cookies=None))
        self.db_session.commit()
