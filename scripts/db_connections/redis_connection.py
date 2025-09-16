from scripts.constants.env_config import DBConf
import redis

user_role_permissions_redis = login_db = redis.from_url(url=DBConf.REDIS_URI, db=int(DBConf.REDIS_LOGIN_DB))
