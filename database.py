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
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    last_domain_change = db.Column(db.DateTime, nullable=True)  # Track when domain was last changed
    changed_by_account = db.Column(db.String(255), nullable=True)  # Track which account made the change

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

class ServerSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_host = db.Column(db.String(255), nullable=False)
    server_port = db.Column(db.Integer, default=22)
    server_username = db.Column(db.String(255), nullable=False)
    server_password = db.Column(db.Text, nullable=True)  # Encrypted password
    server_key_path = db.Column(db.String(500), nullable=True)  # Path to SSH key file
    json_files_path = db.Column(db.String(500), nullable=False, default='/opt/gbot-web-app/accounts/')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
