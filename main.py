import logging
import json
import uuid

from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash

from flask_restful import Resource, Api, reqparse

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
api = Api(app)

app.config["JWT_SECRET_KEY"] = "super-jwt-secret-key"
jwt = JWTManager(app)

try:
    users = json.loads(open("users.json").read())
except Exception as e:
    print(e)
    users = []

try:
    items = json.loads(open("items.json").read())
except Exception as e:
    print(e)
    items = []


# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    u = next(filter(lambda x: x.get("username") == username, users))

    if not username or not password or u:
        return jsonify({"msg": "Bad username or password"}), 401

    if len(password) < 8:
        return jsonify({"msg": "Password min 8 character"}), 401
    user = {
        "id": len(users),
        "uuid": str(uuid.uuid4()),
        "username": username,
        "password": generate_password_hash(password, method="sha256"),
    }
    users.append(user)
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4, ensure_ascii=True)
    return jsonify({"msg": "User already register"}), 201


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = next(filter(lambda x: x.get("username") == username, users))
    if not username or not password or not user:
        return jsonify({"msg": "Bad username or password"}), 401
    if not check_password_hash(user["password"], password):
        return jsonify({"msg": "Bad username or password"}), 401
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route("/items", methods=["GET"])
@jwt_required()
def items():
    return jsonify({"items": "items"}), 200


class Item(Resource):
    @jwt_required()
    def get(self, name):
        return {"get": name}, 200

    @jwt_required()
    def post(self, name):
        return {"post": str(name)}, 201

    @jwt_required()
    def put(self, name):
        return {"put": str(name)}, 204

    @jwt_required()
    def delete(self, name):
        return {"delete": str(name)}, 204


api.add_resource(Item, "/item/<string:name>")

if __name__ == "__main__":
    app.run("0.0.0.0", 5000, debug=True)
