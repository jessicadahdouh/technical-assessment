from dotenv import load_dotenv
import yaml
import os


load_dotenv()

environment = os.getenv('ENVIRONMENT', None)
print("ENV: ", environment)

if environment is None:
    raise ValueError('Environment is not set.')

jwt_secret_key = os.getenv('JWT_SECRET_KEY')

if jwt_secret_key is None:
    raise ValueError('JWT Secret Key is not set.')

secret_key = os.getenv('CRYPTO_SECRET_KEY')

if secret_key is None:
    raise ValueError('Secret Key is not set.')


config_filename = 'config.yml'


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
config_folder = os.path.join(BASE_DIR, "configurations")
config_path = os.path.join(config_folder, config_filename)


# Read YAML file
with open(config_path, "r") as f:
    data = yaml.safe_load(f)


class ProjectConfig:
    DEBUG = False
    main_section = data[environment]
    db_section = main_section['DATABASE']
