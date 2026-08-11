"""PhishGuard — User Model"""
from nexuscore import Schema, Field

register_schema = Schema({
    'username': Field(str).required().min_length(3).max_length(30).alphanumeric(),
    'password': Field(str).required().min_length(12).max_length(128),
    'email':    Field(str).required().email(),
})

login_schema = Schema({
    'username': Field(str).required(),
    'password': Field(str).required(),
})

_users: dict = {}
_by_email: dict = {}

def get_users():
    return _users

def get_by_email():
    return _by_email
