from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import relationship

from solitudeCode import db_utils
from solitudeCode.models import Base


class Connections(Base):
    __tablename__ = 'connections'

    id = Column(Integer, primary_key=True, index=True)
    host = Column(String(255))
    url = Column(Text)
    time = Column(DateTime())
    method = Column(String(16))
    content_length = Column(Integer)
    content_type = Column(String(255))
    user_agent = Column(String(255))
    IP_address = Column(String(20))
    #violations = relationship('Violations', back_populates='connection_ID')#, viewonly=False, sync_backref=False)
    relationship('Violations', back_populates='connection_ID')#, viewonly=False, sync_backref=False)

    def __init__(self, host, url, time, method, content_length, content_type, user_agent, IP_address):
        self.host = host
        self.url = url
        self.time = time
        self.method = method
        self.content_length = content_length
        self.content_type = content_type
        self.user_agent = user_agent
        self.IP_address = IP_address


Base.metadata.create_all(db_utils.return_engine())
