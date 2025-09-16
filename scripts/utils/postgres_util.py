import importlib

from sqlalchemy import Text, create_engine, inspect
from sqlalchemy.orm import Session
from sqlalchemy.sql import text
from sqlalchemy_utils import create_database, database_exists

from scripts.constants.env_config import DBConf
from scripts.logging.logging import logger


class SQLDBUtils:
    def __init__(self, db: Session):
        self.session: Session = db

    def close(self):
        logger.debug("SQL Session closed")
        self.session.close()

    @property
    def key_filter_expression(self):
        return "expression"

    @property
    def key_filter_column(self):
        return "column"

    @property
    def key_filter_value(self):
        return "value"

    def add_data(self, table):
        self.session.add(table)
        self.session.commit()
        self.session.refresh(table)
        return True

    def bulk_insert(self, object_models):
        self.session.bulk_save_objects(object_models)
        self.session.commit()
        return True

    def filter_expression(self):
        filter_expression = self.filter.get(self.key_filter_expression, "eq")
        logger.debug(f"Filter expression: {filter_expression}")
        return filter_expression

    def filter_column(self):
        column = self.filter.get(self.key_filter_column, None)
        logger.debug(f"Filter column: {column}")
        return column

    def filter_value(self):
        filter_value = self.filter.get(self.key_filter_value, None)
        logger.debug(f"Filter value: {filter_value}")
        return filter_value

    def _filter(self, session_query, filters=None):
        if filters is not None:
            for _filter in filters:
                self.filter = _filter
                if self.filter_column() is None:
                    continue
                session_query = self.get_session_query(session_query=session_query)
        return session_query

    def get_session_query(self, session_query):
        try:
            if self.filter_expression() == "eq":
                session_query = session_query.filter(self.filter_column() == self.filter_value())
            if self.filter_expression() == "le":
                session_query = session_query.filter(self.filter_column() < self.filter_value())
            if self.filter_expression() == "ge":
                session_query = session_query.filter(self.filter_column() > self.filter_value())
            if self.filter_expression() == "lte":
                session_query = session_query.filter(self.filter_column() <= self.filter_value())
            if self.filter_expression() == "gte":
                session_query = session_query.filter(self.filter_column() >= self.filter_value())
            if self.filter_expression() == "neq":
                session_query = session_query.filter(self.filter_column() != self.filter_value())
        except Exception as e:
            logger.error(f"Error occurred while filtering the session query {e}")
        return session_query

    def insert_one(self, table, insert_json):
        try:
            row = table()
            for k in insert_json:
                setattr(row, k, insert_json[k])
            self.session.merge(row)
            self.session.commit()
            return True
        except Exception as e:
            logger.error(f"Error while inserting the record {e}")
            raise

    def update(self, table, update_json, filters=None, insert=False, insert_id=None):
        try:
            logger.debug(filters)
            row = self.session.query(table)
            filtered_row = self._filter(session_query=row, filters=filters)
            filtered_row = filtered_row.first()
            if filtered_row is None:
                logger.debug("There are no rows meeting the given update criteria.")
                if insert:
                    logger.debug("Trying to insert a new record")
                    if insert_id is None:
                        logger.warning("ID not provided to insert record. Skipping insert.")
                        return False
                    else:
                        update_json.update(insert_id)
                    if self.insert_one(table=table, insert_json=update_json):
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                logger.debug("Record available to update")
            for k in update_json:
                setattr(filtered_row, k, update_json[k])
            # filtered_row.update()
            self.session.commit()
        except Exception as e:
            logger.error(f"Error while updating the record {e}")
            raise

    def delete(self, table, filters=None):
        try:
            # logger.trace(filters)
            row = self.session.query(table)
            filtered_row = self._filter(session_query=row, filters=filters)
            if filtered_row is None:
                logger.debug("There were no records to be deleted")
            else:
                filtered_row.delete()
                self.session.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to delete a record {e}")
            raise

    def distinct_values_by_column(self, table, column, filters=None):
        query = self.session.query(getattr(table, column).distinct().label(column))
        query = self._filter(session_query=query, filters=filters)
        distinct_values = [getattr(row, column) for row in query.all()]
        return distinct_values

    def select_from_table(self, table=None, query=None):
        if query is None:
            query = f"select * from {table}"
        result = self.session.execute(query)
        return [dict(zip(row.keys(), row.values())) for row in result]

    def fetch_from_table(self, table, filter_text, limit_value, skip_value):
        logger.debug(filter_text)
        row = self.session.query(table).filter(Text(filter_text)).limit(limit_value).offset(skip_value)
        result = self.session.execute(row)
        return [dict(zip(row.keys(), row.values())) for row in result]

    def execute_query(self, table=None, query=None):
        try:
            if query is None:
                query = f"select * from {table}"
            result = self.session.execute(text(query))
            columns = result.keys()._keys
            output = [dict(zip(columns, row)) for row in result]
            self.session.close()
            return output
        except Exception as e:
            logger.error(f"Error occurred during execute_query: {e}")


def create_table(table_name):
    try:
        engine = create_engine(DBConf.POSTGRES_URI, echo=True)
        if not inspect(engine).has_table(table_name):
            # Added to models.tables the new table I needed ( format Table as written above )
            table_models = importlib.import_module("scripts.db.db_models")
            # Grab the class that represents the new table
            # table_name = 'NewTableC'
            orm_table = getattr(table_models, table_name)
            # checkfirst = True to make sure it doesn't exists
            orm_table.__table__.create(bind=engine, checkfirst=True)
    except Exception as e:
        logger.error(f"Error occurred during start-up: {e}", exc_info=True)
    return True


def create_table_logbook_action(table_name):
    try:
        engine = create_engine(DBConf.POSTGRES_URI, echo=True)
        if not inspect(engine).has_table(table_name):
            table_models = importlib.import_module("scripts.db.db_models")
            # Grab the class that represents the new table
            # table_name = 'NewTableC'
            orm_table = getattr(table_models, table_name)
            orm_table.__table__.create(bind=engine, checkfirst=True)
    except Exception as e:
        logger.error(f"Error occurred during start-up: {e}", exc_info=True)


def create_db():
    try:
        engine = create_engine(DBConf.POSTGRES_URI, echo=True)
        if not database_exists(engine.url):
            create_database(engine.url)
    except Exception as e:
        logger.error(f"Error occurred during start-up: {e}", exc_info=True)
    return True
