from datetime import datetime, timezone
from app import db

def utcnow():
    return datetime.now(timezone.utc)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="warga")
    is_active = db.Column(db.Boolean, nullable=False, default=True)

class Resident(db.Model):
    __tablename__ = "residents"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True)
    full_name = db.Column(db.String(160), nullable=False)
    address = db.Column(db.String(255), nullable=False)

class Ticket(db.Model):
    __tablename__ = "tickets"
    id = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(db.Integer, db.ForeignKey("residents.id"), nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Diajukan")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class TicketMessage(db.Model):
    __tablename__ = "ticket_messages"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), nullable=False)
    author_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class Document(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), nullable=False)
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    ciphertext_path = db.Column(db.String(500), nullable=False)
    algorithm = db.Column(db.String(30), nullable=False)
    crypto_metadata_json = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
