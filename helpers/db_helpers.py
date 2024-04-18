from helpers.custom_exceptions import UserAlreadyExistsError
from mongoengine import NotUniqueError
from models.models import Users
from models.schemas import User


def insert_user(record: User):
    try:
        user = Users(username=record.username, password=record.password, is_admin=record.is_admin)
        user.save()
        return True
    except NotUniqueError:
        return 'Found'
    except Exception as e:
        # log the exception
        print(str(e))
        return False


def get_user(username: str):
    try:
        found_user = Users.objects(username=username).first()
        if found_user:
            return found_user
        else:
            return None
    except Exception:
        return False


def save_access_token(username: str, user_access_token: str) -> bool:
    user = Users.objects(username=username).first()
    if user:
        user.access_token = user_access_token
        user.save()
        return True
    else:
        return False


def edit_record(old_user: str, record: User) -> bool:
    try:
        if get_user(record.username):
            raise UserAlreadyExistsError(record.username)

        user = Users.objects(username=old_user).first()

        # Update a document
        user.update(
            set__username=record.username,
            set__password=record.password,
            set__is_admin=record.is_admin
        )

        return True
    except UserAlreadyExistsError:
        raise UserAlreadyExistsError(record.username)
    except Exception:
        return False


def delete_record(username: str) -> bool:
    try:
        found_user = Users.objects(username=username).first()
        if found_user:
            found_user.delete()
            return True
    except Exception:
        return False
