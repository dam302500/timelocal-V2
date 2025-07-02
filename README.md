# TimeLocal API - Version Railway/Render

## 🚀 Déploiement rapide

### Sur Railway
1. Créez un nouveau repo GitHub avec ces fichiers
2. Connectez Railway à votre repo
3. Railway déploiera automatiquement
4. Testez : `https://votre-url.railway.app/health`

### Sur Render
1. "New Web Service" sur render.com
2. Connectez votre repo GitHub
3. Render détecte automatiquement les paramètres
4. Déploiement automatique

## 📁 Fichiers inclus

- `app.py` - Application Flask complète
- `requirements.txt` - Dépendances minimales
- `Procfile` - Configuration Gunicorn
- `runtime.txt` - Version Python
- `railway.json` - Configuration Railway
- `.gitignore` - Fichiers à ignorer

## 🧪 Test de l'API

### Endpoints disponibles
- `GET /` - Informations API
- `GET /health` - Santé de l'API
- `POST /auth/register` - Inscription
- `POST /auth/login` - Connexion
- `GET /requests` - Liste des demandes

### Test d'inscription
```bash
curl -X POST https://votre-url/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "full_name": "Test User"
  }'
```

## ⚙️ Variables d'environnement

### Optionnelles (Railway/Render les gère)
- `SECRET_KEY` - Clé secrète (auto-générée)
- `PORT` - Port (auto-assigné)
- `FLASK_DEBUG` - Mode debug (False par défaut)

## 📊 Fonctionnalités

✅ **Base de données** SQLite persistante  
✅ **Authentification** avec sessions  
✅ **CORS** configuré  
✅ **API REST** complète  
✅ **Gestion d'erreurs** robuste  
✅ **Health check** pour monitoring  

## 🔧 Structure de la base de données

### Users
- id, username, email, password_hash
- full_name, phone, address, bio, skills
- time_credits, points, level, rating
- timestamps

### Requests
- id, user_id, title, description
- category, type (request/offer)
- time_required, price, exchange_type
- status, timestamps

### Exchanges
- id, request_id, requester_id, provider_id
- status, times, ratings, comments
- timestamps

## 🆘 Dépannage

### Erreur de build
- Vérifiez `requirements.txt`
- Vérifiez `runtime.txt`

### Erreur de démarrage
- Consultez les logs Railway/Render
- Vérifiez le `Procfile`

### Base de données
- SQLite se crée automatiquement
- Persistance garantie sur Railway/Render

## 📞 Support

Testez l'API avec `/health` et `/test` pour diagnostiquer les problèmes.