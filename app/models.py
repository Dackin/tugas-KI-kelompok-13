from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    __table_args__ = (
        db.CheckConstraint("role IN ('admin', 'warga')", name="ck_users_role"),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(
        db.String(20), nullable=False, default="warga", server_default="warga"
    )
    is_active = db.Column(
        db.Boolean, nullable=False, default=True, server_default=db.true()
    )
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_login_at = db.Column(db.DateTime(timezone=True))

    resident = db.relationship(
        "Resident",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    uploaded_documents = db.relationship("Document", back_populates="uploaded_by")
    ticket_messages = db.relationship("TicketMessage", back_populates="author")
    audit_logs = db.relationship("AuditLog", back_populates="actor")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    def has_role(self, *roles):
        return self.role in roles

    def __repr__(self):
        return f"<User {self.username!r} role={self.role!r}>"


class Resident(db.Model):
    __tablename__ = "residents"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    full_name = db.Column(db.String(160), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    user = db.relationship("User", back_populates="resident")
    tickets = db.relationship(
        "Ticket",
        back_populates="resident",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<Resident {self.full_name!r}>"


class Ticket(db.Model):
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(
        db.Integer,
        db.ForeignKey("residents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(
        db.String(30), nullable=False, default="Diajukan", index=True
    )
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    resident = db.relationship("Resident", back_populates="tickets")
    messages = db.relationship(
        "TicketMessage",
        back_populates="ticket",
        cascade="all, delete-orphan",
        order_by="TicketMessage.created_at",
    )
    documents = db.relationship(
        "Document",
        back_populates="ticket",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<Ticket {self.id} status={self.status!r}>"


class TicketMessage(db.Model):
    __tablename__ = "ticket_messages"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(
        db.Integer,
        db.ForeignKey("tickets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    ticket = db.relationship("Ticket", back_populates="messages")
    author = db.relationship("User", back_populates="ticket_messages")

    def __repr__(self):
        return f"<TicketMessage {self.id} ticket={self.ticket_id}>"


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(
        db.Integer,
        db.ForeignKey("tickets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    uploaded_by_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    original_filename = db.Column(db.String(255), nullable=False)
    ciphertext_path = db.Column(db.String(500), nullable=False)
    algorithm = db.Column(db.String(30), nullable=False)
    crypto_metadata_json = db.Column(db.Text, nullable=False, default="{}")
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    ticket = db.relationship("Ticket", back_populates="documents")
    uploaded_by = db.relationship("User", back_populates="uploaded_documents")

    def __repr__(self):
        return f"<Document {self.id} {self.original_filename!r}>"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(100))
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    actor = db.relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action!r} {self.resource_type!r}>"
