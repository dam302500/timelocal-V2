#!/usr/bin/env python3
"""
TimeLocal API Enhanced - Version complète avec demandes, messagerie et réservations
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
    CORS_ORIGINS = ['*']  # Permissif pour les tests
    
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
    """Initialise la base de données avec toutes les tables"""
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
                postal_code TEXT,
                bio TEXT,
                skills TEXT,
                time_credits INTEGER DEFAULT 100,
                points INTEGER DEFAULT 0,
                level TEXT DEFAULT 'new_user',
                rating REAL DEFAULT 5.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Table des demandes/offres
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('request', 'offer')),
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                duration TEXT,
                location TEXT,
                postal_code TEXT,
                credits INTEGER DEFAULT 0,
                availability TEXT,
                status TEXT DEFAULT 'active' CHECK (status IN ('active', 'reserved', 'completed', 'cancelled')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            -- Table des réservations
            CREATE TABLE IF NOT EXISTS reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                requester_id INTEGER NOT NULL,
                provider_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined', 'completed', 'cancelled')),
                message TEXT,
                scheduled_date TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests (id),
                FOREIGN KEY (requester_id) REFERENCES users (id),
                FOREIGN KEY (provider_id) REFERENCES users (id)
            );

            -- Table des messages
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                request_id INTEGER,
                reservation_id INTEGER,
                content TEXT NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id),
                FOREIGN KEY (request_id) REFERENCES requests (id),
                FOREIGN KEY (reservation_id) REFERENCES reservations (id)
            );

            -- Index pour améliorer les performances
            CREATE INDEX IF NOT EXISTS idx_requests_user_id ON requests(user_id);
            CREATE INDEX IF NOT EXISTS idx_requests_postal_code ON requests(postal_code);
            CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
            CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
            CREATE INDEX IF NOT EXISTS idx_reservations_requester ON reservations(requester_id);
            CREATE INDEX IF NOT EXISTS idx_reservations_provider ON reservations(provider_id);
        ''')

def get_db():
    """Obtient une connexion à la base de données"""
    return sqlite3.connect(app.config['DATABASE_PATH'])

def dict_factory(cursor, row):
    """Convertit les résultats SQL en dictionnaires"""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

# Décorateurs
def require_auth(f):
    """Décorateur pour vérifier l'authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Routes d'authentification
@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email et mot de passe requis'}), 400
        
        with get_db() as conn:
            conn.row_factory = dict_factory
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                
                # Supprimer les informations sensibles
                user_data = {k: v for k, v in user.items() if k != 'password_hash'}
                
                return jsonify({
                    'success': True,
                    'message': 'Connexion réussie',
                    'user': user_data
                })
            else:
                return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
                
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        full_name = data.get('full_name', '').strip()
        password = data.get('password', '')
        
        if not all([username, email, full_name, password]):
            return jsonify({'error': 'Tous les champs sont requis'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Le mot de passe doit contenir au moins 6 caractères'}), 400
        
        password_hash = generate_password_hash(password)
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT INTO users (username, email, full_name, password_hash)
                    VALUES (?, ?, ?, ?)
                ''', (username, email, full_name, password_hash))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'Utilisateur créé avec succès',
                    'user_id': user_id,
                    'username': username
                }), 201
                
            except sqlite3.IntegrityError:
                return jsonify({'error': 'Nom d\'utilisateur ou email déjà utilisé'}), 409
                
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Déconnexion réussie'})

# Routes des utilisateurs
@app.route('/users/profile', methods=['GET'])
@require_auth
def get_profile():
    try:
        with get_db() as conn:
            conn.row_factory = dict_factory
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            
            if user:
                user_data = {k: v for k, v in user.items() if k != 'password_hash'}
                return jsonify({'user': user_data})
            else:
                return jsonify({'error': 'Utilisateur non trouvé'}), 404
                
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/users/profile', methods=['PUT'])
@require_auth
def update_profile():
    try:
        data = request.get_json()
        
        # Champs autorisés à la mise à jour
        allowed_fields = ['full_name', 'phone', 'address', 'postal_code', 'bio', 'skills']
        update_data = {k: v for k, v in data.items() if k in allowed_fields}
        
        if not update_data:
            return jsonify({'error': 'Aucune donnée à mettre à jour'}), 400
        
        # Construire la requête SQL dynamiquement
        set_clause = ', '.join([f'{k} = ?' for k in update_data.keys()])
        values = list(update_data.values()) + [session['user_id']]
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute(f'''
                UPDATE users 
                SET {set_clause}, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', values)
            
            conn.commit()
            
            return jsonify({'success': True, 'message': 'Profil mis à jour'})
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

# Routes des demandes/offres
@app.route('/requests', methods=['GET'])
def get_requests():
    try:
        # Paramètres de recherche
        category = request.args.get('category', '')
        postal_code = request.args.get('postal_code', '')
        request_type = request.args.get('type', '')  # 'request' ou 'offer'
        limit = int(request.args.get('limit', 50))
        
        query = '''
            SELECT r.*, u.full_name, u.username, u.rating 
            FROM requests r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.status = 'active'
        '''
        params = []
        
        if category:
            query += ' AND r.category = ?'
            params.append(category)
        
        if postal_code:
            query += ' AND r.postal_code = ?'
            params.append(postal_code)
        
        if request_type:
            query += ' AND r.type = ?'
            params.append(request_type)
        
        query += ' ORDER BY r.created_at DESC LIMIT ?'
        params.append(limit)
        
        with get_db() as conn:
            conn.row_factory = dict_factory
            cursor = conn.cursor()
            
            cursor.execute(query, params)
            requests = cursor.fetchall()
            
            return jsonify({'requests': requests})
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/requests', methods=['POST'])
@require_auth
def create_request():
    try:
        data = request.get_json()
        
        required_fields = ['type', 'title', 'description', 'category']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Champs requis manquants'}), 400
        
        if data['type'] not in ['request', 'offer']:
            return jsonify({'error': 'Type invalide'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO requests 
                (user_id, type, title, description, category, duration, location, 
                 postal_code, credits, availability)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                data['type'],
                data['title'],
                data['description'],
                data['category'],
                data.get('duration', ''),
                data.get('location', ''),
                data.get('postal_code', ''),
                data.get('credits', 0),
                data.get('availability', '')
            ))
            
            request_id = cursor.lastrowid
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Demande créée avec succès',
                'request_id': request_id
            }), 201
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

# Routes des réservations
@app.route('/reservations', methods=['POST'])
@require_auth
def create_reservation():
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        message = data.get('message', '')
        scheduled_date = data.get('scheduled_date', '')
        
        if not request_id:
            return jsonify({'error': 'ID de demande requis'}), 400
        
        with get_db() as conn:
            conn.row_factory = dict_factory
            cursor = conn.cursor()
            
            # Vérifier que la demande existe et est active
            cursor.execute('SELECT * FROM requests WHERE id = ? AND status = "active"', (request_id,))
            req = cursor.fetchone()
            
            if not req:
                return jsonify({'error': 'Demande non trouvée ou inactive'}), 404
            
            # Empêcher l'auto-réservation
            if req['user_id'] == session['user_id']:
                return jsonify({'error': 'Vous ne pouvez pas réserver votre propre demande'}), 400
            
            # Déterminer qui est le demandeur et qui est le fournisseur
            if req['type'] == 'request':
                requester_id = req['user_id']
                provider_id = session['user_id']
            else:  # offer
                requester_id = session['user_id']
                provider_id = req['user_id']
            
            cursor.execute('''
                INSERT INTO reservations 
                (request_id, requester_id, provider_id, message, scheduled_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (request_id, requester_id, provider_id, message, scheduled_date))
            
            reservation_id = cursor.lastrowid
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Réservation créée',
                'reservation_id': reservation_id
            }), 201
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/reservations', methods=['GET'])
@require_auth
def get_reservations():
    try:
        with get_db() as conn:
            conn.row_factory = dict_factory
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT res.*, req.title, req.description, req.type,
                       u_req.full_name as requester_name,
                       u_prov.full_name as provider_name
                FROM reservations res
                JOIN requests req ON res.request_id = req.id
                JOIN users u_req ON res.requester_id = u_req.id
                JOIN users u_prov ON res.provider_id = u_prov.id
                WHERE res.requester_id = ? OR res.provider_id = ?
                ORDER BY res.created_at DESC
            ''', (session['user_id'], session['user_id']))
            
            reservations = cursor.fetchall()
            
            return jsonify({'reservations': reservations})
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/reservations/<int:reservation_id>/status', methods=['PUT'])
@require_auth
def update_reservation_status():
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['accepted', 'declined', 'completed', 'cancelled']:
            return jsonify({'error': 'Statut invalide'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Vérifier que l'utilisateur peut modifier cette réservation
            cursor.execute('''
                SELECT * FROM reservations 
                WHERE id = ? AND (requester_id = ? OR provider_id = ?)
            ''', (reservation_id, session['user_id'], session['user_id']))
            
            reservation = cursor.fetchone()
            if not reservation:
                return jsonify({'error': 'Réservation non trouvée'}), 404
            
            cursor.execute('''
                UPDATE reservations 
                SET status = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (new_status, reservation_id))
            
            conn.commit()
            
            return jsonify({'success': True, 'message': 'Statut mis à jour'})
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

# Routes des messages
@app.route('/messages', methods=['GET'])
@require_auth
def get_messages():
    try:
        conversation_with = request.args.get('with')  # ID de l'autre utilisateur
        
        if conversation_with:
            # Messages d'une conversation spécifique
            query = '''
                SELECT m.*, u.full_name as sender_name
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE (m.sender_id = ? AND m.receiver_id = ?) 
                   OR (m.sender_id = ? AND m.receiver_id = ?)
                ORDER BY m.created_at ASC
            '''
            params = [session['user_id'], conversation_with, conversation_with, session['user_id']]
        else:
            # Tous les messages reçus
            query = '''
                SELECT m.*, u.full_name as sender_name
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.receiver_id = ?
                ORDER BY m.created_at DESC
            '''
            params = [session['user_id']]
        
        with get_db() as conn:
            conn.row_factory = dict_factory
            cursor = conn.cursor()
            
            cursor.execute(query, params)
            messages = cursor.fetchall()
            
            return jsonify({'messages': messages})
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/messages', methods=['POST'])
@require_auth
def send_message():
    try:
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content', '').strip()
        request_id = data.get('request_id')
        reservation_id = data.get('reservation_id')
        
        if not receiver_id or not content:
            return jsonify({'error': 'Destinataire et contenu requis'}), 400
        
        if receiver_id == session['user_id']:
            return jsonify({'error': 'Vous ne pouvez pas vous envoyer un message'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO messages 
                (sender_id, receiver_id, content, request_id, reservation_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], receiver_id, content, request_id, reservation_id))
            
            message_id = cursor.lastrowid
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Message envoyé',
                'message_id': message_id
            }), 201
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/messages/<int:message_id>/read', methods=['PUT'])
@require_auth
def mark_message_read():
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE messages 
                SET is_read = TRUE 
                WHERE id = ? AND receiver_id = ?
            ''', (message_id, session['user_id']))
            
            conn.commit()
            
            return jsonify({'success': True})
            
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

# Route de santé
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'version': '2.1.0',
        'database': 'connected',
        'timestamp': datetime.now().isoformat(),
        'features': ['auth', 'requests', 'reservations', 'messages', 'geolocation']
    })

# Route racine
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'name': 'TimeLocal API Enhanced',
        'version': '2.1.0',
        'description': 'API complète pour l\'échange de temps et services',
        'endpoints': {
            'auth': ['/auth/login', '/auth/register', '/auth/logout'],
            'users': ['/users/profile'],
            'requests': ['/requests'],
            'reservations': ['/reservations'],
            'messages': ['/messages'],
            'health': ['/health']
        }
    })

# Initialisation et démarrage
if __name__ == '__main__':
    init_db()
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=app.config['DEBUG']
    )
