from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from passlib.hash import pbkdf2_sha256
from marshmallow import Schema, fields, ValidationError
from datetime import datetime, timedelta
import os
from flask_restful import Api

app = Flask(__name__)
app.config.from_pyfile('configure.py')

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["JWT_SECRET_KEY"] = "jose"
api = Api(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='categories', lazy=True)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)


class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    password = fields.Str(load_only=True, required=True)


class CategorySchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    is_default = fields.Bool(default=False)


class ExpenseSchema(Schema):
    id = fields.Int(dump_only=True)
    amount = fields.Float(required=True)
    date = fields.DateTime(default=datetime.utcnow)
    description = fields.Str()
    user_id = fields.Int(required=True)
    category_id = fields.Int(required=True)


@app.route('/register', methods=['POST'])
def register():
    username = request.args.get('username')
    password = request.args.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400

    user = User(
        username=username,
        password=pbkdf2_sha256.hash(password)
    )
    db.session.add(user)
    db.session.commit()

    user_schema = UserSchema()
    return jsonify(user_schema.dump(user)), 201


@app.route('/login', methods=['POST'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if user and pbkdf2_sha256.verify(password, user.password):
        access_token = create_access_token(identity=str(user.id), fresh=False)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"message": "The token has expired.", "error": "token_expired"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"message": "Signature verification failed.", "error": "invalid_token"}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "description": "Request does not contain an access token.",
        "error": "authorization_required"
    }), 401


@app.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    user_id = request.args.get("user_id", type=int)

    if user_id:
        categories = Category.query.filter_by(user_id=user_id).all()
    else:
        categories = Category.query.filter_by(is_default=True).all()

    category_schema = CategorySchema(many=True)
    return jsonify(category_schema.dump(categories))


@app.route('/categories', methods=['POST'])
@jwt_required()
def create_category():
    name = request.args.get("name")
    is_default = request.args.get("is_default", type=bool, default=False)

    if not name:
        return jsonify({"message": "Category name is required"}), 400

    user_id = None
    if not is_default:
        user_id = get_jwt_identity()

    new_category = Category(
        name=name,
        is_default=is_default,
        user_id=user_id
    )

    db.session.add(new_category)
    db.session.commit()

    category_schema = CategorySchema()
    return jsonify(category_schema.dump(new_category)), 201


@app.route('/expenses', methods=['POST'])
@jwt_required()
def create_expense():
    amount = request.args.get("amount", type=float)
    category_id = request.args.get("category_id", type=int)
    description = request.args.get("description", default="")

    if not amount or not category_id:
        return jsonify({"message": "Amount and Category ID are required"}), 400

    user_id = get_jwt_identity()
    category = Category.query.filter_by(id=category_id).first()

    if category and category.user_id != user_id and not category.is_default:
        return jsonify({"message": "You are not allowed to add expense to this category"}), 403

    new_expense = Expense(
        amount=amount,
        description=description,
        user_id=user_id,
        category_id=category_id
    )

    db.session.add(new_expense)
    db.session.commit()

    expense_schema = ExpenseSchema()
    return jsonify(expense_schema.dump(new_expense)), 201


@app.route('/expenses', methods=['GET'])
@jwt_required()
def get_expenses():
    user_id = get_jwt_identity()
    category_id = request.args.get("category_id", type=int)

    query = Expense.query.filter_by(user_id=user_id)

    if category_id:
        query = query.filter_by(category_id=category_id)

    expenses = query.all()
    expense_schema = ExpenseSchema(many=True)
    return jsonify(expense_schema.dump(expenses))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
