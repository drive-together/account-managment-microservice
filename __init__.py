from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from prometheus_flask_exporter import PrometheusMetrics
from sqlalchemy import text
import logging
import logstash
from flasgger import Swagger
from routes.main import main_bp
from models.user import db


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('settings.py')
    
    CORS(app)

    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    metrics = PrometheusMetrics(app)

    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/account-managment/apispec.json',
                "rule_filter": lambda rule: True,  # all in
                "model_filter": lambda tag: True,  # all in
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/openapi"
    }
    template = {
        "swagger": "2.0",
        "basePath": "/account-managment",
    }
    swagger = Swagger(app, config=swagger_config, template=template)

    # Register blueprints
    app.register_blueprint(main_bp)

    # Create the database tables
    with app.app_context():
        db.create_all()

    @app.route('/', methods=['GET'])
    def index():
        return jsonify(), 200
    
    @app.route('/livez', methods=['GET'])
    def health_check_liveness():
        return jsonify(status='ok', message='Health check passed'), 200
        
    @app.route('/readyz', methods=['GET'])
    def health_check_readiness():
        try:
            db.session.execute(text('SELECT 1'))
            return jsonify(status='ok', message='Health check passed'), 200
        except Exception as e:
            return jsonify(status='error', message=f'Health check failed: {str(e)}'), 500       

    logger = logging.getLogger('python-logstash-logger')
    logger.setLevel(logging.INFO)
    logger.addHandler(logstash.UDPLogstashHandler(
        host=app.config.get('LOGIT_IO_HOST'), 
        port=int(app.config.get('LOGIT_IO_PORT')),
        version=1
    ))

    app.logger.addHandler(logger)

    return app