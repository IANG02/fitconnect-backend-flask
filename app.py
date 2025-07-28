# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
import datetime
from functools import wraps

# --- App Initialization ---
app = Flask(__name__)
CORS(app) # Allow cross-origin requests from your React frontend

# --- Configuration ---
# Replace with your MySQL connection details
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:88888888@localhost/fitconnect_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_super_secret_key' # Change this to a random secret key

# --- Database and Security Setup ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False) # 'client' or 'trainer'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    profile = db.relationship('TrainerProfile', backref='user', uselist=False, cascade="all, delete-orphan")
    services = db.relationship('Service', backref='trainer', lazy=True, cascade="all, delete-orphan")
    bookings_as_client = db.relationship('Booking', foreign_keys='Booking.client_id', backref='client', lazy=True)
    bookings_as_trainer = db.relationship('Booking', foreign_keys='Booking.trainer_id', backref='booking_trainer', lazy=True)

class TrainerProfile(db.Model):
    __tablename__ = 'trainer_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    specialty = db.Column(db.String(255), default='Fitness Expert')
    bio = db.Column(db.Text, default='A passionate and dedicated fitness professional.')
    avatar_url = db.Column(db.String(255), default='default_avatar.png')

class Service(db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    trainer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)

class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    trainer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    booking_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='confirmed') # e.g., confirmed, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- Security Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['userId'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- API Routes ---

# --- User Authentication APIs ---
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'This email is already registered.'}), 409
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(name=data['name'], email=data['email'], password=hashed_password, role=data['role'])
    if new_user.role == 'trainer':
        new_user.profile = TrainerProfile()
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid email or password.'}), 401
    token = jwt.encode({
        'userId': user.id, 'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'message': 'Login successful!', 'token': token}), 200

# --- Trainers APIs ---
@app.route('/api/trainers', methods=['GET'])
def get_all_trainers():
    trainers = User.query.filter_by(role='trainer').all()
    output = []
    for trainer in trainers:
        profile = trainer.profile
        trainer_data = {
            'id': trainer.id, 'name': trainer.name, 'email': trainer.email,
            'specialty': profile.specialty if profile else 'N/A',
            'bio': profile.bio if profile else 'N/A'
        }
        output.append(trainer_data)
    return jsonify(output), 200

@app.route('/api/trainers/<int:trainer_id>', methods=['GET'])
def get_single_trainer(trainer_id):
    trainer = User.query.filter_by(id=trainer_id, role='trainer').first()
    if not trainer: return jsonify({'message': 'Trainer not found.'}), 404
    profile = trainer.profile
    trainer_data = {
        'id': trainer.id, 'name': trainer.name, 'email': trainer.email,
        'specialty': profile.specialty if profile else 'N/A',
        'bio': profile.bio if profile else 'N/A'
    }
    return jsonify(trainer_data), 200

@app.route('/api/trainers/me', methods=['PUT'])
@token_required
def update_my_profile(current_user):
    if current_user.role != 'trainer':
        return jsonify({'message': 'This function is only for trainers.'}), 403
    data = request.get_json()
    profile = current_user.profile
    if not profile:
        profile = TrainerProfile(user_id=current_user.id)
        db.session.add(profile)
    profile.specialty = data.get('specialty', profile.specialty)
    profile.bio = data.get('bio', profile.bio)
    current_user.name = data.get('name', current_user.name)
    db.session.commit()
    return jsonify({'message': 'Profile updated successfully!'}), 200

# --- Services APIs (for Trainers) ---
@app.route('/api/services', methods=['POST'])
@token_required
def create_service(current_user):
    if current_user.role != 'trainer':
        return jsonify({'message': 'Only trainers can create services.'}), 403
    data = request.get_json()
    new_service = Service(
        trainer_id=current_user.id,
        name=data['name'],
        description=data.get('description', ''),
        price=data['price'],
        duration_minutes=data['duration_minutes']
    )
    db.session.add(new_service)
    db.session.commit()
    return jsonify({'message': 'Service created successfully!', 'id': new_service.id}), 201

@app.route('/api/services/<int:service_id>', methods=['PUT'])
@token_required
def update_service(current_user, service_id):
    service = Service.query.get(service_id)
    if not service: return jsonify({'message': 'Service not found.'}), 404
    if service.trainer_id != current_user.id:
        return jsonify({'message': 'You can only edit your own services.'}), 403
    data = request.get_json()
    service.name = data.get('name', service.name)
    service.description = data.get('description', service.description)
    service.price = data.get('price', service.price)
    service.duration_minutes = data.get('duration_minutes', service.duration_minutes)
    db.session.commit()
    return jsonify({'message': 'Service updated successfully!'}), 200

@app.route('/api/services/<int:service_id>', methods=['DELETE'])
@token_required
def delete_service(current_user, service_id):
    service = Service.query.get(service_id)
    if not service: return jsonify({'message': 'Service not found.'}), 404
    if service.trainer_id != current_user.id:
        return jsonify({'message': 'You can only delete your own services.'}), 403
    db.session.delete(service)
    db.session.commit()
    return jsonify({'message': 'Service deleted successfully!'}), 200

# --- Bookings APIs (for Clients) ---
@app.route('/api/bookings', methods=['POST'])
@token_required
def create_booking(current_user):
    if current_user.role != 'client':
        return jsonify({'message': 'Only clients can create bookings.'}), 403
    data = request.get_json()
    new_booking = Booking(
        client_id=current_user.id,
        trainer_id=data['trainer_id'],
        service_id=data['service_id'],
        booking_time=datetime.datetime.fromisoformat(data['booking_time'])
    )
    db.session.add(new_booking)
    db.session.commit()
    return jsonify({'message': 'Booking created successfully!', 'id': new_booking.id}), 201

@app.route('/api/bookings/me', methods=['GET'])
@token_required
def get_my_bookings(current_user):
    if current_user.role == 'client':
        bookings = Booking.query.filter_by(client_id=current_user.id).all()
    elif current_user.role == 'trainer':
        bookings = Booking.query.filter_by(trainer_id=current_user.id).all()
    else:
        return jsonify([]), 200
    
    output = []
    for booking in bookings:
        output.append({
            'id': booking.id,
            'client_id': booking.client_id,
            'trainer_id': booking.trainer_id,
            'service_id': booking.service_id,
            'booking_time': booking.booking_time.isoformat(),
            'status': booking.status
        })
    return jsonify(output), 200

# --- Run the Application ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
