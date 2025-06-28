# app.py - Point d'entrée principal
import os
import secrets
from flask import Flask, request, jsonify, send_from_directory, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import stripe

# Configuration de l'application
app = Flask(__name__)
app.config.from_object('config')

# Configuration de la base de données
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL',
                                                  'postgresql://user:password@localhost/sciences_univers')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = 'protected_uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'pptx', 'zip'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# Clé Stripe (à mettre dans les variables d'environnement)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# Initialisation des extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


# Modèles de données
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_premium = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Program(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)


class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    program_id = db.Column(db.Integer, db.ForeignKey('program.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(200), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # 'course', 'resource', 'exam'
    is_premium = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    program = db.relationship('Program', backref=db.backref('resources', lazy=True))


class DownloadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'))
    downloaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    ip_address = db.Column(db.String(45))


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stripe_price_id = db.Column(db.String(50))


# Sécurité
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth:
            return jsonify({"error": "Authentification requise"}), 401

        try:
            token = auth.split(" ")[1]
            user = User.query.filter_by(api_token=token).first()
            if not user:
                return jsonify({"error": "Token invalide"}), 401

            g.current_user = user
        except Exception as e:
            return jsonify({"error": "Authentification échouée", "details": str(e)}), 401

        return f(*args, **kwargs)

    return decorated_function


def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.current_user.is_premium:
            return jsonify({"error": "Accès premium requis"}), 403
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.current_user.is_admin:
            return jsonify({"error": "Accès administrateur requis"}), 403
        return f(*args, **kwargs)

    return decorated_function


# Utilitaires
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def log_download(user_id, resource_id):
    try:
        log = DownloadLog(
            user_id=user_id,
            resource_id=resource_id,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Échec de journalisation du téléchargement: {str(e)}")


# Routes API
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()

    if not user or not user.check_password(data.get('password')):
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    # Créer un token JWT dans une version réelle
    token = secrets.token_urlsafe(32)
    user.api_token = token
    db.session.commit()

    return jsonify({
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_premium": user.is_premium
        }
    })


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"error": "L'email est déjà utilisé"}), 400

    user = User(
        email=data['email'],
        full_name=data['full_name']
    )
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Compte créé avec succès"}), 201


@app.route('/api/programs', methods=['GET'])
def get_programs():
    programs = Program.query.all()
    return jsonify([{
        "id": p.id,
        "name": p.name,
        "slug": p.slug,
        "description": p.description,
        "category": p.category
    } for p in programs])


@app.route('/api/programs/<slug>', methods=['GET'])
def get_program(slug):
    program = Program.query.filter_by(slug=slug).first_or_404()
    resources = Resource.query.filter_by(program_id=program.id).all()

    return jsonify({
        "program": {
            "id": program.id,
            "name": program.name,
            "description": program.description
        },
        "resources": [{
            "id": r.id,
            "title": r.title,
            "type": r.resource_type,
            "is_premium": r.is_premium
        } for r in resources]
    })


@app.route('/api/resources/<int:resource_id>/download', methods=['GET'])
@auth_required
def download_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)

    if resource.is_premium and not g.current_user.is_premium:
        return jsonify({"error": "Accès premium requis"}), 403

    # Journaliser le téléchargement
    log_download(g.current_user.id, resource_id)

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        resource.file_path,
        as_attachment=True
    )


@app.route('/api/services', methods=['GET'])
def get_services():
    services = Service.query.all()
    return jsonify([{
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "price": s.price,
        "stripe_price_id": s.stripe_price_id
    } for s in services])


@app.route('/api/payments/create-intent', methods=['POST'])
@auth_required
def create_payment_intent():
    data = request.get_json()

    try:
        intent = stripe.PaymentIntent.create(
            amount=int(data['amount'] * 100),  # Convertir en centimes
            currency='eur',
            customer=g.current_user.stripe_customer_id,
            metadata={
                "user_id": g.current_user.id,
                "service_id": data.get('service_id'),
                "premium_subscription": data.get('premium', False)
            }
        )
        return jsonify({
            "clientSecret": intent.client_secret
        })
    except stripe.error.StripeError as e:
        return jsonify({"error": str(e)}), 400


# Administration
@app.route('/api/admin/upload-resource', methods=['POST'])
@admin_required
def upload_resource():
    if 'file' not in request.files:
        return jsonify({"error": "Aucun fichier fourni"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Nom de fichier vide"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Type de fichier non autorisé"}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    data = request.form
    resource = Resource(
        program_id=data['program_id'],
        title=data['title'],
        description=data.get('description', ''),
        file_path=filename,
        resource_type=data['resource_type'],
        is_premium=bool(data.get('is_premium'))
    )

    db.session.add(resource)
    db.session.commit()

    return jsonify({
        "message": "Ressource téléchargée avec succès",
        "resource_id": resource.id
    }), 201


# Webhooks Stripe
@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError as e:
        return jsonify({"error": "Payload invalide"}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({"error": "Signature invalide"}), 400

    # Gérer les événements Stripe
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        handle_payment_success(payment_intent)

    return jsonify({"status": "success"})


def handle_payment_success(payment_intent):
    metadata = payment_intent.get('metadata', {})
    user_id = metadata.get('user_id')
    service_id = metadata.get('service_id')
    premium = metadata.get('premium_subscription', 'false') == 'true'

    if user_id:
        user = User.query.get(user_id)
        if premium:
            user.is_premium = True
            db.session.commit()
        # Traiter les commandes de services...


# Sécurité supplémentaire
@app.after_request
def add_security_headers(resp):
    resp.headers[
        'Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://js.stripe.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:;"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return resp


if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # HTTPS en développement