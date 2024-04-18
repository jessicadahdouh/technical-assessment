from mongoengine import Document, StringField, BinaryField, BooleanField
from settings import ProjectConfig, secret_key
from helpers.crypto.cipher import DataCipher
from helpers.utils import connect_to_mongo


decipher = DataCipher(hex_key=secret_key)
db_section = ProjectConfig.db_section
connection_vars = [
                    'MONGODB_HOST',
                    'MONGODB_PORT',
                    'MONGODB_USER',
                    'MONGODB_PASSWORD',
                    'MONGODB_AUTH_DB',
                    'MONGODB_DATABASE'
                   ]

data = {
    key: decipher.decrypt_data(db_section.get(key)) if db_section.get(key) else None
    for key in connection_vars
}

# Check if data['MONGODB_DATABASE'] is None
if data['MONGODB_DATABASE'] is None:
    database_name = "DynamicEyeUsers"
else:
    database_name = data['MONGODB_DATABASE']


connect_to_mongo(host=data['MONGODB_HOST'], port=data['MONGODB_PORT'],
                 username=data['MONGODB_USER'], password=data['MONGODB_PASSWORD'],
                 auth_db=data['MONGODB_AUTH_DB'], database=database_name)


class Users(Document):
    meta = {
        'collection': 'de_users'
    }

    username = StringField(required=True, unique=True)
    password = BinaryField(required=True)
    access_token = StringField()
    is_admin = BooleanField(default=False)
