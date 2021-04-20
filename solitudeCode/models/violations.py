from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary, Text

from solitudeCode import db_utils
from solitudeCode.models import Base


class Violations(Base):
    __tablename__ = 'violations'

    id = Column(Integer, primary_key=True, index=True)
    violation_message = Column(String(10000))
    connection_ID = Column(Integer, ForeignKey('connections.id'), index=True)
    body = Column(LargeBinary(length=(2**32)-1))
    cookies = Column(Text)
    phorcies_object = Column(LargeBinary(length=(2**32)-1))

    def __init__(self, violation_message, body, phorcies_object, cookies, connection_ID):
        self.connection_ID = connection_ID
        self.violation_message = violation_message
        self.body = body
        self.cookies = cookies
        self.phorcies_object = phorcies_object


Base.metadata.create_all(db_utils.return_engine())
