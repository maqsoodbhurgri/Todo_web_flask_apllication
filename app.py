from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional


app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY="change-this-to-a-secret-key",
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{app.root_path}/app.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    tasks = db.relationship("Task", backref="owner", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(6, 128)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class TaskForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    description = TextAreaField("Description", validators=[Optional(), Length(max=2000)])
    due_date = DateField("Due date", validators=[Optional()], format="%Y-%m-%d")
    category = StringField("Category", validators=[Optional(), Length(max=100)])
    submit = SubmitField("Save")


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first():
            flash("User with that username or email already exists", "warning")
            return render_template("register.html", form=form)
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "").strip()
    sort = request.args.get("sort", "created_desc")
    cat = request.args.get("category", "")

    tasks = Task.query.filter_by(user_id=current_user.id)
    if q:
        tasks = tasks.filter(
            (Task.title.ilike(f"%{q}%")) | (Task.description.ilike(f"%{q}%")) | (Task.category.ilike(f"%{q}%"))
        )
    if cat:
        tasks = tasks.filter(Task.category == cat)

    if sort == "due_asc":
        tasks = tasks.order_by(Task.due_date.asc().nulls_last())
    elif sort == "due_desc":
        tasks = tasks.order_by(Task.due_date.desc().nulls_last())
    elif sort == "title_asc":
        tasks = tasks.order_by(Task.title.asc())
    elif sort == "title_desc":
        tasks = tasks.order_by(Task.title.desc())
    else:
        tasks = tasks.order_by(Task.created_at.desc())

    tasks = tasks.all()
    categories = db.session.query(Task.category).filter_by(user_id=current_user.id).distinct()
    return render_template("dashboard.html", tasks=tasks, q=q, sort=sort, categories=categories)


@app.route("/task/add", methods=["GET", "POST"])
@login_required
def add_task():
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(
            title=form.title.data,
            description=form.description.data,
            due_date=form.due_date.data,
            category=form.category.data,
            user_id=current_user.id,
            is_active=True,
        )
        db.session.add(task)
        db.session.commit()
        flash("Task added.", "success")
        return redirect(url_for("dashboard"))
    return render_template("task_form.html", form=form, action="Add Task")


@app.route("/task/edit/<int:task_id>", methods=["GET", "POST"])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for("dashboard"))
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        form.populate_obj(task)
        db.session.commit()
        flash("Task updated.", "success")
        return redirect(url_for("dashboard"))
    return render_template("task_form.html", form=form, action="Edit Task")


@app.route("/task/delete/<int:task_id>", methods=["POST"])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for("dashboard"))
    db.session.delete(task)
    db.session.commit()
    flash("Task deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/task/toggle/<int:task_id>", methods=["POST"])
@login_required
def toggle_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return ("", 403)
    task.is_active = not task.is_active
    db.session.commit()
    return redirect(url_for("dashboard"))


def init_db():
    with app.app_context():
        db.create_all()


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
