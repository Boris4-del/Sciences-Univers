from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import os
import uuid
import logging
import stripe
import re
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration de l'application Flask
app = Flask(__name__, static_folder='../frontend', static_url_path='/')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///sciences_univers.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialiser les extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configurer Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLIC_KEY = os.getenv('STRIPE_PUBLIC_KEY')

# Configurer le logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SciencesUnivers')


# Modèles de données
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, default=lambda: str(uuid.uuid4()))
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    study_level = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), default='student')
    premium = db.Column(db.Boolean, default=False)
    premium_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    courses = db.relationship('UserCourse', backref='user', lazy=True)
    payments = db.relationship('Payment', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'public_id': self.public_id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'study_level': self.study_level,
            'role': self.role,
            'premium': self.premium,
            'premium_expiry': self.premium_expiry.isoformat() if self.premium_expiry else None,
            'created_at': self.created_at.isoformat()
        }


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('CourseFile', backref='course', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'price': self.price,
            'year': self.year,
            'created_at': self.created_at.isoformat()
        }


class CourseFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    file_type = db.Column(db.String(20), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'course_id': self.course_id,
            'filename': self.filename,
            'display_name': self.display_name,
            'file_type': self.file_type,
            'is_premium': self.is_premium,
            'created_at': self.created_at.isoformat()
        }


class UserCourse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_id = db.Column(db.Integer, db.ForeignKey('payment.id'))
    course = db.relationship('Course', backref='user_courses')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'course_id': self.course_id,
            'purchase_date': self.purchase_date.isoformat(),
            'course': self.course.to_dict() if self.course else None
        }


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='EUR')
    status = db.Column(db.String(20), default='pending')
    stripe_payment_id = db.Column(db.String(100))
    payment_method = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_course = db.relationship('UserCourse', backref='payment', uselist=False)

    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'currency': self.currency,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'payment_method': self.payment_method
        }


class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='new')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'subject': self.subject,
            'message': self.message,
            'created_at': self.created_at.isoformat(),
            'status': self.status
        }


# Middleware et utilitaires
@app.before_request
def before_request():
    # Générer un token CSRF pour chaque requête
    if request.endpoint != 'static':
        csrf_token = generate_csrf()
        session['csrf_token'] = csrf_token


def validate_email(email):
    """Valider le format de l'email"""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Valider la force du mot de passe"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True


def get_current_user():
    """Récupérer l'utilisateur actuellement connecté"""
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    return None


def create_payment_intent(amount, currency='eur'):
    """Créer un PaymentIntent avec Stripe"""
    try:
        payment_intent = stripe.PaymentIntent.create(
            amount=int(amount * 100),  # Convertir en centimes
            currency=currency,
            automatic_payment_methods={
                'enabled': True,
            },
        )
        return payment_intent
    except stripe.error.StripeError as e:
        logger.error(f"Erreur Stripe: {e}")
        return None


# Routes API
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Obtenir un token CSRF"""
    return jsonify({'csrf_token': generate_csrf()})


@app.route('/api/register', methods=['POST'])
def register():
    """Inscription d'un nouvel utilisateur"""
    data = request.get_json()

    # Validation des données
    required_fields = ['first_name', 'last_name', 'email', 'password', 'study_level']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Le champ {field} est requis'}), 400

    if not validate_email(data['email']):
        return jsonify({'error': 'Adresse email invalide'}), 400

    if not validate_password(data['password']):
        return jsonify({
                           'error': 'Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre'}), 400

    # Vérifier si l'email existe déjà
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Un compte existe déjà avec cet email'}), 409

    # Créer un nouvel utilisateur
    new_user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        study_level=data['study_level']
    )
    new_user.set_password(data['password'])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'message': 'Compte créé avec succès',
        'user': new_user.to_dict()
    }), 201


@app.route('/api/login', methods=['POST'])
def login():
    """Connexion d'un utilisateur"""
    data = request.get_json()

    # Validation des données
    if 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email et mot de passe requis'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    # Mettre à jour la session
    session['user_id'] = user.id
    user.last_login = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'message': 'Connexion réussie',
        'user': user.to_dict()
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    """Déconnexion de l'utilisateur"""
    session.pop('user_id', None)
    return jsonify({'message': 'Déconnexion réussie'})


@app.route('/api/user', methods=['GET'])
def get_current_user_info():
    """Obtenir les informations de l'utilisateur connecté"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401

    return jsonify(user.to_dict())


@app.route('/api/courses', methods=['GET'])
def get_courses():
    """Obtenir la liste des cours"""
    courses = Course.query.all()
    return jsonify([course.to_dict() for course in courses])


@app.route('/api/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    """Obtenir les détails d'un cours spécifique"""
    course = Course.query.get(course_id)
    if not course:
        return jsonify({'error': 'Cours non trouvé'}), 404

    course_data = course.to_dict()
    course_data['files'] = [file.to_dict() for file in course.files]
    return jsonify(course_data)


@app.route('/api/user/courses', methods=['GET'])
def get_user_courses():
    """Obtenir les cours achetés par l'utilisateur"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401

    user_courses = UserCourse.query.filter_by(user_id=user.id).all()
    return jsonify([uc.to_dict() for uc in user_courses])


@app.route('/api/purchase', methods=['POST'])
def purchase_course():
    """Acheter un cours"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401

    data = request.get_json()
    if 'course_id' not in data:
        return jsonify({'error': 'ID du cours requis'}), 400

    course = Course.query.get(data['course_id'])
    if not course:
        return jsonify({'error': 'Cours non trouvé'}), 404

    # Vérifier si l'utilisateur a déjà acheté ce cours
    existing_purchase = UserCourse.query.filter_by(
        user_id=user.id,
        course_id=course.id
    ).first()

    if existing_purchase:
        return jsonify({'error': 'Vous avez déjà acheté ce cours'}), 400

    # Créer un PaymentIntent Stripe
    payment_intent = create_payment_intent(course.price)
    if not payment_intent:
        return jsonify({'error': 'Erreur lors de la création du paiement'}), 500

    # Créer un enregistrement de paiement
    payment = Payment(
        user_id=user.id,
        amount=course.price,
        currency='EUR',
        status='requires_payment_method',
        stripe_payment_id=payment_intent['id']
    )
    db.session.add(payment)
    db.session.commit()

    return jsonify({
        'message': 'Paiement initié',
        'client_secret': payment_intent['client_secret'],
        'payment_id': payment.id
    })


@app.route('/api/payment/confirm', methods=['POST'])
def confirm_payment():
    """Confirmer un paiement réussi"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401

    data = request.get_json()
    if 'payment_id' not in data or 'course_id' not in data:
        return jsonify({'error': 'ID de paiement et de cours requis'}), 400

    payment = Payment.query.get(data['payment_id'])
    course = Course.query.get(data['course_id'])

    if not payment or not course:
        return jsonify({'error': 'Paiement ou cours non trouvé'}), 404

    if payment.user_id != user.id:
        return jsonify({'error': 'Non autorisé'}), 403

    # Vérifier le statut du paiement avec Stripe
    try:
        stripe_payment = stripe.PaymentIntent.retrieve(payment.stripe_payment_id)
        if stripe_payment.status != 'succeeded':
            return jsonify({'error': 'Paiement non réussi'}), 400
    except stripe.error.StripeError as e:
        logger.error(f"Erreur Stripe: {e}")
        return jsonify({'error': 'Erreur de vérification du paiement'}), 500

    # Mettre à jour le statut du paiement
    payment.status = 'succeeded'
    payment.payment_method = stripe_payment.payment_method_types[0] if stripe_payment.payment_method_types else 'card'

    # Enregistrer l'achat du cours
    user_course = UserCourse(
        user_id=user.id,
        course_id=course.id,
        payment_id=payment.id
    )
    db.session.add(user_course)
    db.session.commit()

    return jsonify({
        'message': 'Paiement confirmé et cours acheté avec succès',
        'course': course.to_dict()
    })


@app.route('/api/premium/subscribe', methods=['POST'])
def subscribe_premium():
    """Souscrire à un abonnement premium"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401

    data = request.get_json()
    if 'plan' not in data:
        return jsonify({'error': 'Plan d\'abonnement requis'}), 400

    plans = {
        'monthly': {'price': 19.99, 'days': 30},
        'quarterly': {'price': 49.99, 'days': 90},
        'yearly': {'price': 149.99, 'days': 365}
    }

    if data['plan'] not in plans:
        return jsonify({'error': 'Plan invalide'}), 400

    plan = plans[data['plan']]

    # Créer un PaymentIntent Stripe
    payment_intent = create_payment_intent(plan['price'])
    if not payment_intent:
        return jsonify({'error': 'Erreur lors de la création du paiement'}), 500

    # Créer un enregistrement de paiement
    payment = Payment(
        user_id=user.id,
        amount=plan['price'],
        currency='EUR',
        status='requires_payment_method',
        stripe_payment_id=payment_intent['id']
    )
    db.session.add(payment)
    db.session.commit()

    return jsonify({
        'message': 'Paiement d\'abonnement initié',
        'client_secret': payment_intent['client_secret'],
        'payment_id': payment.id
    })


@app.route('/api/premium/confirm', methods=['POST'])
def confirm_premium():
    """Confirmer un abonnement premium réussi"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non authentifié'}), 401

    data = request.get_json()
    if 'payment_id' not in data or 'plan' not in data:
        return jsonify({'error': 'ID de paiement et plan requis'}), 400

    plans = {
        'monthly': {'price': 19.99, 'days': 30},
        'quarterly': {'price': 49.99, 'days': 90},
        'yearly': {'price': 149.99, 'days': 365}
    }

    if data['plan'] not in plans:
        return jsonify({'error': 'Plan invalide'}), 400

    plan = plans[data['plan']]
    payment = Payment.query.get(data['payment_id'])

    if not payment:
        return jsonify({'error': 'Paiement non trouvé'}), 404

    if payment.user_id != user.id:
        return jsonify({'error': 'Non autorisé'}), 403

    # Vérifier le statut du paiement avec Stripe
    try:
        stripe_payment = stripe.PaymentIntent.retrieve(payment.stripe_payment_id)
        if stripe_payment.status != 'succeeded':
            return jsonify({'error': 'Paiement non réussi'}), 400
    except stripe.error.StripeError as e:
        logger.error(f"Erreur Stripe: {e}")
        return jsonify({'error': 'Erreur de vérification du paiement'}), 500

    # Mettre à jour le statut du paiement
    payment.status = 'succeeded'
    payment.payment_method = stripe_payment.payment_method_types[0] if stripe_payment.payment_method_types else 'card'

    # Activer l'abonnement premium
    user.premium = True
    if user.premium_expiry and user.premium_expiry > datetime.utcnow():
        # Prolonger l'abonnement existant
        user.premium_expiry += timedelta(days=plan['days'])
    else:
        # Nouvel abonnement
        user.premium_expiry = datetime.utcnow() + timedelta(days=plan['days'])

    db.session.commit()

    return jsonify({
        'message': 'Abonnement premium activé avec succès',
        'premium_expiry': user.premium_expiry.isoformat()
    })


@app.route('/api/contact', methods=['POST'])
def submit_contact():
    """Soumettre un message de contact"""
    data = request.get_json()

    # Validation des données
    required_fields = ['name', 'email', 'subject', 'message']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Le champ {field} est requis'}), 400

    if not validate_email(data['email']):
        return jsonify({'error': 'Adresse email invalide'}), 400

    # Créer un nouveau message
    contact_message = ContactMessage(
        name=data['name'],
        email=data['email'],
        subject=data['subject'],
        message=data['message']
    )

    db.session.add(contact_message)
    db.session.commit()

    # Ici vous pourriez ajouter une intégration avec un service d'email
    logger.info(f"Nouveau message de contact: {data['subject']} de {data['name']}")

    return jsonify({
        'message': 'Votre message a été envoyé avec succès',
        'contact_id': contact_message.id
    })


@app.route('/api/files/<int:file_id>', methods=['GET'])
def download_file(file_id):
    """Télécharger un fichier"""
    user = get_current_user()
    course_file = CourseFile.query.get(file_id)

    if not course_file:
        return jsonify({'error': 'Fichier non trouvé'}), 404

    # Vérifier l'accès au fichier
    if course_file.is_premium:
        if not user or not user.premium:
            return jsonify({'error': 'Accès premium requis'}), 403

    # Vérifier si le fichier existe
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], course_file.filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'Fichier introuvable sur le serveur'}), 404

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        course_file.filename,
        as_attachment=True,
        download_name=f"{secure_filename(course_file.display_name)}.{course_file.file_type}"
    )


# Route pour servir le frontend
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    """Servir l'application frontend"""
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')


# Gestion des erreurs
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Ressource non trouvée'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erreur serveur: {error}")
    return jsonify({'error': 'Erreur interne du serveur'}), 500


if __name__ == '__main__':
    # Créer le dossier d'upload s'il n'existe pas
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Créer les tables si elles n'existent pas
    with app.app_context():
        db.create_all()

    # Démarrer l'application
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc' if os.getenv('FLASK_ENV') == 'production' else None)