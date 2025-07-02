#!/usr/bin/env python3
"""
TimeLocal API - Version optimisée pour Railway
Version simplifiée et stable pour déploiement cloud
"""

import os
import sqlite3
import json
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import secrets

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    DATABASE_PATH = 'timelocal.db'
    CORS_ORIGINS = ['*']  # Permissif pour les tests, restrictif en production
    
    # Variables d'environnement optionnelles
    APP_URL = os.environ.get('APP_URL', 'http://localhost:5000')
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

# Création de l'application Flask
app = Flask(__name__)
app.config.from_object(Config)

# Configuration CORS
CORS(app, 
     origins=app.config['CORS_ORIGINS'],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Utilitaires base de données
def init_db():
    """Initialise la base de données avec les tables essentielles"""
    with sqlite3.connect(app.config['DATABASE_PATH']) as conn:
        conn.executescript('''
            -- Table des utilisateurs
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                phone TEXT,
                address TEXT,
                bio TEXT,
                skills TEXT,
                time_credits INTEGER DEFAULT 100,
                level TEXT DEFAULT 'new_user',
                points INTEGER DEFAULT 0,
                rating REAL DEFAULT 5.0,
                rating_count INTEGER DEFAULT 0,
                is_verified BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Table des demandes/offres
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                type TEXT NOT NULL, -- 'request' ou 'offer'
                time_required INTEGER, -- en minutes
                price REAL DEFAULT 0,
                exchange_type TEXT DEFAULT 'time', -- 'time', 'money', 'hybrid'
                location TEXT,
                deadline TIMESTAMP,
                status TEXT DEFAULT 'active', -- 'active', 'completed', 'cancelled'
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            
            -- Table des échanges
            CREATE TABLE IF NOT EXISTS exchanges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                requester_id INTEGER NOT NULL,
                provider_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending', -- 'pending', 'accepted', 'completed', 'cancelled'
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                time_spent INTEGER, -- en minutes
                amount_paid REAL DEFAULT 0,
                rating_requester INTEGER,
                rating_provider INTEGER,
                comment_requester TEXT,
                comment_provider TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests (id),
                FOREIGN KEY (requester_id) REFERENCES users (id),
                FOREIGN KEY (provider_id) REFERENCES users (id)
            );
            
            -- Index pour les performances
            CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
            CREATE INDEX IF NOT EXISTS idx_exchanges_status ON exchanges(status);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        ''')

def get_db():
    """Obtient une connexion à la base de données"""
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """Décorateur pour vérifier la connexion utilisateur"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Routes principales
@app.route('/')
def index():
    """Page d'accueil de l'API"""
    return jsonify({
        'app': 'TimeLocal API',
        'version': '2.0.0',
        'status': 'running',
        'message': 'API TimeLocal déployée avec succès!',
        'deployment': 'Railway/Render',
        'endpoints': {
            'health': '/health',
            'auth': {
                'register': 'POST /auth/register',
                'login': 'POST /auth/login',
                'logout': 'POST /auth/logout'
            },
            'users': {
                'profile': 'GET /users/profile',
                'update': 'PUT /users/profile'
            },
            'requests': {
                'list': 'GET /requests',
                'create': 'POST /requests'
            }
        }
    })

@app.route('/health')
def health():
    """Endpoint de santé pour Railway/Render"""
    try:
        # Test de connexion à la base de données
        with get_db() as conn:
            conn.execute('SELECT 1').fetchone()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'deployment': 'success',
            'version': '2.0.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Routes d'authentification
@app.route('/auth/register', methods=['POST'])
def register():
    """Inscription d'un nouvel utilisateur"""
    try:
        # Gestion des données JSON et form-data
        data = request.get_json() if request.is_json else request.form.to_dict()
        
        # Validation des données
        required_fields = ['username', 'email', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'error': f'Champs manquants: {", ".join(missing_fields)}'
            }), 400
        
        # Validation email basique
        if '@' not in data['email']:
            return jsonify({'error': 'Email invalide'}), 400
        
        # Validation mot de passe
        if len(data['password']) < 6:
            return jsonify({'error': 'Mot de passe trop court (min 6 caractères)'}), 400
        
        with get_db() as conn:
            # Vérifier si l'utilisateur existe déjà
            existing = conn.execute(
                'SELECT id FROM users WHERE username = ? OR email = ?',
                (data['username'], data['email'])
            ).fetchone()
            
            if existing:
                return jsonify({'error': 'Nom d\'utilisateur ou email déjà utilisé'}), 409
            
            # Créer l'utilisateur
            password_hash = generate_password_hash(data['password'])
            cursor = conn.execute('''
                INSERT INTO users (username, email, password_hash, full_name, phone, bio, skills)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['username'],
                data['email'],
                password_hash,
                data.get('full_name', data['username']),
                data.get('phone', ''),
                data.get('bio', ''),
                data.get('skills', '')
            ))
            
            user_id = cursor.lastrowid
            
            # Créer une session
            session['user_id'] = user_id
            session['username'] = data['username']
            session.permanent = True
            
            return jsonify({
                'message': 'Utilisateur créé avec succès',
                'user_id': user_id,
                'username': data['username'],
                'success': True
            }), 201
            
    except Exception as e:
        return jsonify({
            'error': f'Erreur serveur: {str(e)}',
            'success': False
        }), 500

@app.route('/auth/login', methods=['POST'])
def login():
    """Connexion utilisateur"""
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email et mot de passe requis'}), 400
        
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE email = ? AND is_active = TRUE',
                (data['email'],)
            ).fetchone()
            
            if not user or not check_password_hash(user['password_hash'], data['password']):
                return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
            
            # Mise à jour de la dernière connexion
            conn.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user['id'],)
            )
            
            # Créer une session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True
            
            return jsonify({
                'message': 'Connexion réussie',
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'full_name': user['full_name'],
                    'email': user['email'],
                    'time_credits': user['time_credits'],
                    'points': user['points'],
                    'level': user['level'],
                    'rating': user['rating']
                }
            })
            
    except Exception as e:
        return jsonify({
            'error': f'Erreur serveur: {str(e)}',
            'success': False
        }), 500

@app.route('/auth/logout', methods=['POST'])
@login_required
def logout():
    """Déconnexion utilisateur"""
    session.clear()
    return jsonify({
        'message': 'Déconnexion réussie',
        'success': True
    })

# Routes utilisateurs
@app.route('/users/profile', methods=['GET'])
@login_required
def get_profile():
    """Obtenir le profil de l'utilisateur connecté"""
    try:
        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE id = ?',
                (session['user_id'],)
            ).fetchone()
            
            if not user:
                return jsonify({'error': 'Utilisateur non trouvé'}), 404
            
            # Convertir en dictionnaire en excluant le mot de passe
            user_dict = dict(user)
            user_dict.pop('password_hash', None)
            
            return jsonify({
                'user': user_dict,
                'success': True
            })
            
    except Exception as e:
        return jsonify({
            'error': f'Erreur serveur: {str(e)}',
            'success': False
        }), 500

@app.route('/users/profile', methods=['PUT'])
@login_required
def update_profile():
    """Mettre à jour le profil utilisateur"""
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        
        # Champs modifiables
        updatable_fields = ['full_name', 'phone', 'address', 'bio', 'skills']
        updates = []
        values = []
        
        for field in updatable_fields:
            if field in data:
                updates.append(f'{field} = ?')
                values.append(data[field])
        
        if not updates:
            return jsonify({'error': 'Aucune donnée à mettre à jour'}), 400
        
        with get_db() as conn:
            values.append(session['user_id'])
            conn.execute(f'''
                UPDATE users 
                SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', values)
            
            return jsonify({
                'message': 'Profil mis à jour avec succès',
                'success': True
            })
            
    except Exception as e:
        return jsonify({
            'error': f'Erreur serveur: {str(e)}',
            'success': False
        }), 500

# Routes des demandes/offres
@app.route('/requests', methods=['GET'])
def get_requests():
    """Obtenir les demandes/offres"""
    try:
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 20)), 50)  # Max 50
        offset = (page - 1) * limit
        
        with get_db() as conn:
            # Compter le total
            total = conn.execute(
                'SELECT COUNT(*) as count FROM requests WHERE status = "active"'
            ).fetchone()['count']
            
            # Récupérer les demandes
            requests = conn.execute('''
                SELECT r.*, u.username, u.full_name, u.rating, u.rating_count
                FROM requests r
                JOIN users u ON r.user_id = u.id
                WHERE r.status = 'active'
                ORDER BY r.created_at DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset)).fetchall()
            
            return jsonify({
                'requests': [dict(req) for req in requests],
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total,
                    'pages': (total + limit - 1) // limit
                },
                'success': True
            })
            
    except Exception as e:
        return jsonify({
            'error': f'Erreur serveur: {str(e)}',
            'success': False
        }), 500

@app.route('/requests', methods=['POST'])
@login_required
def create_request():
    """Créer une nouvelle demande/offre"""
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        
        # Validation des données
        required_fields = ['title', 'description', 'category', 'type']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'error': f'Champs manquants: {", ".join(missing_fields)}'
            }), 400
        
        # Validation du type
        if data['type'] not in ['request', 'offer']:
            return jsonify({'error': 'Type invalide (request ou offer)'}), 400
        
        with get_db() as conn:
            cursor = conn.execute('''
                INSERT INTO requests (
                    user_id, title, description, category, type, 
                    time_required, price, exchange_type, location, deadline
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                data['title'],
                data['description'],
                data['category'],
                data['type'],
                int(data.get('time_required', 60)),
                float(data.get('price', 0)),
                data.get('exchange_type', 'time'),
                data.get('location', ''),
                data.get('deadline')
            ))
            
            request_id = cursor.lastrowid
            
            return jsonify({
                'message': 'Demande créée avec succès',
                'request_id': request_id,
                'success': True
            }), 201
            
    except Exception as e:
        return jsonify({
            'error': f'Erreur serveur: {str(e)}',
            'success': False
        }), 500

# Routes de test
@app.route('/test', methods=['GET', 'POST'])
def test():
    """Endpoint de test pour valider le déploiement"""
    return jsonify({
        'message': 'Test API réussi',
        'method': request.method,
        'timestamp': datetime.utcnow().isoformat(),
        'deployment': 'Railway/Render OK',
        'database': 'SQLite connecté',
        'session_support': 'Actif',
        'cors': 'Configuré'
    })

# Gestion des erreurs
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint non trouvé',
        'message': 'Vérifiez l\'URL et la méthode HTTP',
        'available_endpoints': [
            '/', '/health', '/test',
            '/auth/register', '/auth/login', '/auth/logout',
            '/users/profile', '/requests'
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Erreur interne du serveur',
        'message': 'Contactez l\'administrateur si le problème persiste'
    }), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'error': 'Méthode HTTP non autorisée',
        'message': 'Vérifiez la méthode HTTP utilisée (GET, POST, PUT, DELETE)'
    }), 405

# Configuration des sessions
app.permanent_session_lifetime = timedelta(days=7)

# Initialisation de la base de données
with app.app_context():
    init_db()
    print("✅ Base de données initialisée")

# Point d'entrée pour les serveurs de production
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = app.config.get('DEBUG', False)
    
    print(f"🚀 Démarrage TimeLocal API sur le port {port}")
    print(f"🔧 Mode debug: {debug}")
    print(f"🔑 Secret key configurée: {'✅' if app.config['SECRET_KEY'] else '❌'}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)

# Export pour Gunicorn (Railway/Render)
application = app