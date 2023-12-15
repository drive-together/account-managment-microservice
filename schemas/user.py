from graphene import ObjectType, Schema, List, String, ID, Field
from models.user import User

class UserType(ObjectType):
    username = String()
    id = ID()

class Query(ObjectType):
    users = List(UserType)
    user = Field(UserType, id=ID()) 

    def resolve_users(self, info):
        return User.query.all()
    
    def resolve_user(self, info, id):
        return User.query.filter_by(id=id).first()

schema = Schema(query=Query)