from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='support')

class WhitelistedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)

class UsedDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    user_count = db.Column(db.Integer, default=0)
    is_verified = db.Column(db.Boolean, default=False)
    ever_used = db.Column(db.Boolean, default=False)  # Track if domain was ever used
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class GoogleAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(255), unique=True, nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    tokens = db.relationship('GoogleToken', backref='account', lazy=True, cascade="all, delete-orphan")

google_token_scopes = db.Table('google_token_scopes',
    db.Column('google_token_id', db.Integer, db.ForeignKey('google_token.id'), primary_key=True),
    db.Column('scope_id', db.Integer, db.ForeignKey('scope.id'), primary_key=True)
)

class Scope(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)

class GoogleToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('google_account.id'), nullable=False)
    token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text)
    token_uri = db.Column(db.Text, nullable=False)
    scopes = db.relationship('Scope', secondary=google_token_scopes, lazy='subquery',
                             backref=db.backref('google_tokens', lazy=True))

class ServerConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=22)
    username = db.Column(db.String(255), nullable=False)
    auth_method = db.Column(db.String(50), default='password')  # 'password' or 'key'
    password = db.Column(db.Text)  # Encrypted password
    private_key = db.Column(db.Text)  # Encrypted private key
    json_path = db.Column(db.String(500), nullable=False)
    file_pattern = db.Column(db.String(100), default='*.json')
    is_configured = db.Column(db.Boolean, default=False)
    last_tested = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class UserAppPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)  # username part (before @)
    domain = db.Column(db.String(255), nullable=False)   # domain part (after @)
    app_password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    # Composite unique constraint on username + domain
    __table_args__ = (db.UniqueConstraint('username', 'domain', name='unique_user_domain'),)

class AutomationAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(255), unique=True, nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    accounts_list = db.Column(db.Text, nullable=False)  # Column-based storage, one account per line
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    last_retrieval = db.Column(db.DateTime)
    retrieval_count = db.Column(db.Integer, default=0)
    
    # Relationship to store retrieved users
    retrieved_users = db.relationship('RetrievedUser', backref='automation_account', lazy=True, cascade="all, delete-orphan")

class RetrievedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    automation_account_id = db.Column(db.Integer, db.ForeignKey('automation_account.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255))
    domain = db.Column(db.String(255))
    status = db.Column(db.String(50), default='active')  # active, suspended, etc.
    retrieved_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Composite unique constraint on automation_account_id + email
    __table_args__ = (db.UniqueConstraint('automation_account_id', 'email', name='unique_automation_user'),)