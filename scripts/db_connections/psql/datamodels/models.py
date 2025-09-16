import shortuuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, inspect, TIMESTAMP
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from scripts.db_connections.psql.database_engine import Base


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(22), primary_key=True, default=shortuuid.uuid)
    email = Column(String(255), unique=True, nullable=False)
    password = Column(Text, nullable=False)
    full_name = Column(String(255))
    user_type = Column(String(50), default="traveller", nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_logged_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    traveller_profile = relationship("TravellerProfile", back_populates="user", uselist=False)
    organizer_profiles = relationship("OrganizerProfile", back_populates="user", uselist=False)

    def to_dict(self, exclude: list = None):
        exclude = exclude or []
        return {
            c.key: getattr(self, c.key)
            for c in inspect(self).mapper.column_attrs
            if c.key not in exclude
        }

class TravellerProfile(Base):
    __tablename__ = "traveller_profiles"

    traveller_id = Column(String(22), primary_key=True, default=shortuuid.uuid)
    user_id = Column(String(22), ForeignKey("users.user_id", ondelete="CASCADE"), unique=True, nullable=False)
    date_of_birth = Column(String(50))
    gender = Column(String(20))
    contact_number = Column(String(20))
    address = Column(Text)
    preferences = Column(JSONB)
    passport_number = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="traveller_profile")

    def to_dict(self, exclude: list = None):
        exclude = exclude or []
        return {
            c.key: getattr(self, c.key)
            for c in inspect(self).mapper.column_attrs
            if c.key not in exclude
        }


class OrganizerProfile(Base):
    __tablename__ = "organizer_profiles"

    organizer_id = Column(String(22), primary_key=True, default=shortuuid.uuid)
    user_id = Column(String(22), ForeignKey("users.user_id", ondelete="CASCADE"), unique=True, nullable=False)
    company_name = Column(String(255), nullable=False)
    license_number = Column(String(100))
    gst_number = Column(String(50))
    contact_number = Column(String(20))
    address = Column(Text)
    bank_account_number = Column(String(50))
    bank_ifsc_code = Column(String(20))
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="organizer_profiles")

    def to_dict(self):
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}