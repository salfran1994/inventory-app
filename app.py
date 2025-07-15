from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from forms import RegisterForm, ChangePasswordForm, EditItemForm, LoginForm
import pandas as pd
import io
import os

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-unsafe-key")

# DataBase Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

### MODELS ###
# User table
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(10), default='user') # option here is 'admin' or 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Item table
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # NEW
    user = db.relationship('User', backref='items')  # Optional but useful

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()


### Login setup ###
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function
    
### 

### ROUTES ###
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)	


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

### ADMIN routes ###
@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Cannot delete admin user.')
        return redirect(url_for('manage_users'))

    # Optional: delete their items too
    Item.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted.")
    return redirect(url_for('manage_users'))


@app.route('/')
@login_required
def index():
    query = request.args.get('q')
    items = Item.query.filter_by(user_id=current_user.id)

    if query:
        items = items.filter(Item.name.contains(query))

    items = items.all()
    return render_template('index.html', inventory=items, query=query)


@app.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form['name']
    quantity = request.form['quantity']
    category = request.form['category']

    new_item = Item(name=name, quantity=int(quantity), category=category,  user_id=current_user.id)
    db.session.add(new_item)
    db.session.commit()

    return redirect(url_for('index'))
    
 
@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.role != 'admin':
        abort(403)
        
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = 'user'#form.role.data

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('User registered successfully!')
        return redirect(url_for('index'))

    return render_template('register.html', form=form)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.')
            return redirect(url_for('change_password'))

        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash('Password updated successfully.')
        return redirect(url_for('index'))

    return render_template('change_password.html', form=form)



@app.route('/delete/<int:item_id>')
@login_required
def delete(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit(item_id):
    item = Item.query.get_or_404(item_id)
    if request.method == 'POST':
        item.name = request.form['name']
        item.quantity = int(request.form['quantity'])
        item.category = request.form['category']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit.html', item=item)
    

@app.route('/update-quantity', methods=['POST'])
@login_required
def update_quantity():
    item_id = request.form.get('item_id')
    quantity = request.form.get('quantity')

    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    if not item:
        return "Unauthorized", 403

    try:
        item.quantity = int(quantity)
        db.session.commit()
        return "OK", 200
    except:
        return "Invalid quantity", 400


### CSV Export / Import ###
@app.route('/export')
@login_required
def export_csv():
    items = Item.query.all()
    df = pd.DataFrame([{'Name': item.name, 'Quantity': item.quantity, 'Category': item.category} for item in items])
    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    buffer.seek(0)
    return send_file(io.BytesIO(buffer.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='inventary.csv')


@app.route('/import', methods=['POST'])
@login_required
def import_csv():
    file = request.files['file']
    if file and file.filename.endswith('.csv'):
        df = pd.read_csv(file)
        for _, row in df.iterrows():
            item = Item(name=row['Name'], quantity=int(row['Quantity']), category=row['Category'], user_id=current_user.id)
            db.session.add(item)
        db.session.commit()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=5000)
