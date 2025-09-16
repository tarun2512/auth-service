from typing import Optional, Dict, Any
from uuid import UUID as PyUUID

from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from scripts.db_connections.psql.datamodels.models import User, OrganizerProfile
from scripts.logging.logging import logger, logging_config


class OrganizerQueryLayer:
    def __init__(self, db: Session):
        self.session: Session = db
        self.echo = logging_config["level"].upper() == "DEBUG"
        self.user_table_obj = User
        self.organizer_profile_obj = OrganizerProfile
        self.create_table(self.user_table_obj)

    def _log_debug(self, msg: str):
        """Helper to conditionally log debug messages."""
        if self.echo:
            logger.debug(msg)

    def create_table(self, table):
        try:
            engine = self.session.get_bind().engine
            if not inspect(engine).has_table(table.__tablename__):
                orm_table = table
                orm_table.__table__.create(bind=engine, checkfirst=True)
        except Exception as e:
            logger.error(f"Error occurred during start-up: {e}", exc_info=True)

    # =====================
    # USER OPERATIONS
    # =====================

    def get_user_by_email(self, email: str) -> Optional[User]:
        try:
            return self.session.query(User).filter(User.email == email).first()
        except SQLAlchemyError as e:
            logger.error(f"Database error fetching user by email {email}: {e}")
            return None

    def get_user_by_id(self, user_id: PyUUID) -> Optional[User]:
        try:
            return self.session.query(User).filter(User.user_id == user_id).first()
        except SQLAlchemyError as e:
            logger.error(f"Database error fetching user by ID {user_id}: {e}")
            return None

    def create_user(self, user_data: Dict[str, Any]) -> Optional[User]:
        try:
            valid_columns = {column.key for column in inspect(User).mapper.column_attrs}
            filtered_data = {key: value for key, value in user_data.items() if key in valid_columns}
            user = User(**filtered_data)
            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
            self._log_debug(f"Created user: {user.email}")
            return user.user_id
        except SQLAlchemyError as e:
            logger.error(f"Failed to create user: {e}", exc_info=True)
            self.session.rollback()
            return None

    def update_user(self, query: Dict[str, Any], update_data: Dict[str, Any]) -> bool:
        try:
            result = self.session.query(User).filter_by(**query).update(update_data)
            if result == 0:
                return False
            self.session.commit()
            self._log_debug(f"Updated user ID: {query.get('user_id')}")
            return True
        except SQLAlchemyError as e:
            logger.error(f"Failed to update user {query.get('user_id')}: {e}", exc_info=True)
            self.session.rollback()
            return False

    def delete_user(self, user_id: PyUUID) -> bool:
        try:
            result = self.session.query(User).filter(User.user_id == user_id).delete()
            if result == 0:
                return False
            self.session.commit()
            self._log_debug(f"Deleted user ID: {user_id}")
            return True
        except SQLAlchemyError as e:
            logger.error(f"Failed to delete user {user_id}: {e}", exc_info=True)
            self.session.rollback()
            return False

    # ===============================
    # ORGANIZER PROFILE OPERATIONS
    # ===============================

    def get_organizer_profile_by_user_id(self, user_id: PyUUID) -> Optional[OrganizerProfile]:
        try:
            return self.session.query(OrganizerProfile).filter(OrganizerProfile.user_id == user_id).first()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching organizer profile for user {user_id}: {e}")
            return None

    def create_organizer_profile(self, profile_data: Dict[str, Any]) -> Optional[OrganizerProfile]:
        try:
            valid_columns = {column.key for column in inspect(OrganizerProfile).mapper.column_attrs}
            filtered_data = {key: value for key, value in profile_data.items() if key in valid_columns}
            profile = OrganizerProfile(**filtered_data)
            self.session.add(profile)
            self.session.commit()
            self.session.refresh(profile)
            self._log_debug(f"Created organizer profile for user: {profile.user_id}")
            return profile
        except SQLAlchemyError as e:
            logger.error(f"Failed to create organizer profile: {e}", exc_info=True)
            self.session.rollback()
            return None

    def update_organizer_profile(self, user_id: PyUUID, update_data: Dict[str, Any]) -> bool:
        try:
            result = self.session.query(OrganizerProfile).filter(
                OrganizerProfile.user_id == user_id
            ).update(update_data)
            if result == 0:
                return False
            self.session.commit()
            self._log_debug(f"Updated organizer profile for user: {user_id}")
            return True
        except SQLAlchemyError as e:
            logger.error(f"Failed to update organizer profile {user_id}: {e}", exc_info=True)
            self.session.rollback()
            return False

    # =======================
    # UPSERT (Insert or Update)
    # =======================

    def upsert_user(self, user_data: Dict[str, Any]) -> Optional[User]:
        """
        Insert new user or update if exists (by email or user_id).
        """
        email = user_data.get("email")
        user_id = user_data.get("user_id")

        try:
            if email:
                user = self.session.query(User).filter(User.email == email).first()
            elif user_id:
                user = self.session.query(User).filter(User.user_id == user_id).first()
            else:
                return self.create_user(user_data)

            if user:
                for key, value in user_data.items():
                    if value is not None:  # Only update non-None values
                        setattr(user, key, value)
                self.session.commit()
                self.session.refresh(user)
                self._log_debug(f"Upserted existing user: {email}")
                return user
            else:
                return self.create_user(user_data)
        except SQLAlchemyError as e:
            logger.error(f"Failed to upsert user {email}: {e}", exc_info=True)
            self.session.rollback()
            return None

    def upsert_organizer_profile(self, profile_data: Dict[str, Any]) -> Optional[OrganizerProfile]:
        """
        Insert or update organizer profile by user_id.
        """
        user_id = profile_data.get("user_id")
        if not user_id:
            logger.error("Cannot upsert organizer profile: missing user_id")
            return None

        try:
            profile = self.session.query(OrganizerProfile).filter(OrganizerProfile.user_id == user_id).first()

            if profile:
                for key, value in profile_data.items():
                    if value is not None:
                        setattr(profile, key, value)
                self.session.commit()
                self.session.refresh(profile)
                self._log_debug(f"Updated organizer profile for user: {user_id}")
            else:
                profile = OrganizerProfile(**profile_data)
                self.session.add(profile)
                self.session.commit()
                self.session.refresh(profile)
                self._log_debug(f"Created new organizer profile for user: {user_id}")

            return profile
        except SQLAlchemyError as e:
            logger.error(f"Failed to upsert organizer profile {user_id}: {e}", exc_info=True)
            self.session.rollback()
            return None
