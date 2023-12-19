from flask import Blueprint, jsonify, request, render_template
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from prometheus_flask_exporter import PrometheusMetrics
import logging
from flask_graphql import GraphQLView
from timeout_decorator import timeout
from circuitbreaker import circuit, CircuitBreakerError
from models.user import db, User
from schemas.user import schema as user_schema

main_bp = Blueprint('main', __name__)
metrics = PrometheusMetrics(main_bp)
logger = logging.getLogger('python-logstash-logger')
extra = {
    'service': 'ride_sharing',
}

login_counter = metrics.counter(
    'login_counter',
    'Number of successful logins',
    labels={'endpoint': '/api/login'}
)

@main_bp.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@main_bp.route('/register', methods=['GET'])
def register_page():
    """
    Endpoint to perform some operation.

    ---
    responses:
      200:
        description: Successful operation
      500:
        description: An error occurred
    """
    return render_template('register.html')

@main_bp.route('/api/register', methods=['POST'])
def register_user():
    """
    Endpoint to perform some operation.

    ---
    parameters:
      - name: user_id
        in: query
        type: integer
        required: true
        description: The ID of the user.
    responses:
      200:
        description: Successful operation
      500:
        description: An error occurred
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify(message='Username and password are required'), 400

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify(message='Username already exists'), 400

    new_user = User(username=username,)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.id)
    
    return jsonify(message='User registered successfully', user=new_user.to_dict(), access_token=access_token), 201

@main_bp.route('/api/login', methods=['POST'])
@login_counter
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify(message='Username and password are required'), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        logger.info(f'Successful login for user: {username}', extra=extra)

        access_token = create_access_token(identity=user.id)
        return jsonify(message='Login successful', user=user.to_dict(), access_token=access_token)

    return jsonify(message='Invalid username or password'), 401


@main_bp.route('/api/users', methods=['POST'])
def users():
    return GraphQLView.as_view('graphql', schema=user_schema, graphiql=True)()
    


@timeout(5) #TODO test on linux
def timeout(seconds):
    import time
    time.sleep(seconds)

@main_bp.route('/api/timeout_test/<int:seconds>', methods=['GET'])
async def timeout_test(seconds):
    try:
        timeout(seconds)
        return jsonify("OK"), 200
    except Exception as e:
        return jsonify(None), 200 #Fallback
    

@circuit(failure_threshold=2, expected_exception=TimeoutError)
@main_bp.route('/api/circuit_breaker_test', methods=['GET'])
def circuit_breaker_test():
    timeout(6)