from flask import Blueprint, jsonify, request, render_template
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from prometheus_flask_exporter import PrometheusMetrics
import logging
from flask_graphql import GraphQLView
from models.user import db, User
from schemas.user import schema as user_schema

main_bp = Blueprint('main', __name__)
metrics = PrometheusMetrics(main_bp)
logger = logging.getLogger('python-logstash-logger')
extra = {
    'service': 'account-management-microservice',
}

login_counter = metrics.counter(
    'login_counter',
    'Number of login calls',
    labels={'endpoint': '/api/login'}
)
register_counter = metrics.counter(
    'register_counter',
    'Number of registration calls',
    labels={'endpoint': '/api/register'}
)
graphql_users_counter = metrics.counter(
    'graphql_users_counter',
    'Number of GraphQL calls',
    labels={'endpoint': '/users'}
)

@main_bp.route('/login', methods=['GET'])
def login_page():
    """
    Renders the login page.

    ---
    responses:
      200:
        description: Returns the HTML page for login.
    """
    logger.info("Login page rendered", extra=extra)
    return render_template('login.html')

@main_bp.route('/register', methods=['GET'])
def register_page():
    """
    Renders the register page.

    ---
    responses:
      200:
        description: Returns the HTML page for registration.
    """
    logger.info("Register page rendered", extra=extra)
    return render_template('register.html')

@main_bp.route('/api/register', methods=['POST'])
@register_counter
def register_user():
    """
    Registers a new user.

    ---
    parameters:
      - name: User
        in: body
        type: object
        required: true
        schema:
            id: User
            properties:
                username:
                    type: string
                    description: The username for the user.
                password:
                    type: string
                    description: The password for the user.
    responses:
      201:
        description: User registered successfully.
      400:
        description: Bad request. Username and password are required.
      400:
        description: Bad request. Username already exists.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.info("Registration failed: Username and password are required", extra=extra)
        return jsonify(message='Username and password are required'), 400

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        logger.info(f'Username already exists: {username}', extra=extra)
        return jsonify(message='Username already exists'), 400

    new_user = User(username=username,)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.id)
    
    logger.info(f'User registered successfully: {username}', extra=extra)
    return jsonify(message='User registered successfully', user=new_user.to_dict(), access_token=access_token), 201

@main_bp.route('/api/login', methods=['POST'])
@login_counter
def login():
    """
    Logs in a user.

    ---
    parameters:
      - name: User
        in: body
        type: object
        required: true
        schema:
            id: User
            properties:
                username:
                    type: string
                    description: The username for the user.
                password:
                    type: string
                    description: The password for the user.
    responses:
      200:
        description: Login successful.
      400:
        description: Bad request. Username and password are required.
      401:
        description: Unauthorized. Invalid username or password.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        logger.info("Login failed: Username and password are required", extra=extra)

        return jsonify(message='Username and password are required'), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        logger.info(f'Successful login for user: {username}', extra=extra)

        access_token = create_access_token(identity=user.id)
        return jsonify(message='Login successful', user=user.to_dict(), access_token=access_token)

    logger.info(f'Login failed: Invalid username or password for user: {username}', extra=extra)
    return jsonify(message='Invalid username or password'), 401


@main_bp.route('/api/users', methods=['POST'])
@graphiql_users_counter
def users():
    """
    GraphQL endpoint for user-related operations.

    ---
    parameters:
      - name: Query
        in: body
        type: string
        required: true
    responses:
      200:
        description: Returns GraphQL data.
    """
    return GraphQLView.as_view('graphql', schema=user_schema, graphiql=True)()