from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from functools import wraps
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # Altere para uma chave segura em produção

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo de Usuário com campo para grupo/role
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='espectador')  # Valores: admin, validador, espectador

# Modelo para Problema com novos campos para notificação
class Problem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved = db.Column(db.Boolean, default=True)  # Se False, precisa de aprovação
    solutions = db.relationship('Solution', backref='problem', lazy=True)

# Modelo para Solução
class Solution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    problem_id = db.Column(db.Integer, db.ForeignKey('problem.id'), nullable=False)

# Criação das tabelas e criação do usuário admin padrão, se não existir
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", password_hash=generate_password_hash("admin"), role="admin")
        db.session.add(admin)
        db.session.commit()

# Decorador para rotas que requerem login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para verificar se o usuário possui uma role específica.
# Se o usuário for admin, ele sempre terá acesso.
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = User.query.get(session.get('user_id'))
            if user is None:
                flash("Acesso não autorizado.", "danger")
                return redirect(url_for('index'))
            if user.role == 'admin':
                return f(*args, **kwargs)
            if user.role not in roles:
                flash("Acesso não autorizado.", "danger")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Tela de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            error = 'Credenciais inválidas. Tente novamente.'
    return render_template('login.html', error=error)

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Página de Configuração (além das opções já existentes, para admin exibe link para gerenciamento de usuários)
@app.route('/config', methods=['GET', 'POST'])
@login_required
def config():
    user = User.query.get(session['user_id'])
    return render_template('config.html', user_role=user.role)

# Rota para alterar a senha do usuário logado (acesso liberado para todos)
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    user = User.query.get(session['user_id'])
    if not check_password_hash(user.password_hash, current_password):
        flash('Senha atual incorreta.', 'danger')
    elif new_password != confirm_password:
        flash('Nova senha e confirmação não coincidem.', 'danger')
    else:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Senha alterada com sucesso!', 'success')
    return redirect(url_for('config'))

# Rota para adicionar um novo usuário (apenas admin pode cadastrar novos usuários)
@app.route('/add_user', methods=['POST'])
@login_required
@role_required('admin')
def add_user():
    username = request.form.get('new_username')
    password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password_new')
    role = request.form.get('role')
    if password != confirm_password:
        flash('Senha e confirmação não coincidem.', 'danger')
    elif User.query.filter_by(username=username).first():
        flash('Usuário já existe.', 'danger')
    else:
        new_user = User(username=username, password_hash=generate_password_hash(password), role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Novo usuário adicionado com sucesso!', 'success')
    return redirect(url_for('config'))

# Rotas de Gerenciamento de Usuários (apenas admin)
@app.route('/users')
@login_required
@role_required('admin')
def list_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    if request.method == 'POST':
        new_role = request.form.get('role')
        user_to_edit.role = new_role
        db.session.commit()
        flash('Permissão atualizada com sucesso!', 'success')
        return redirect(url_for('list_users'))
    return render_template('edit_user.html', user=user_to_edit)

@app.route('/delete_user/<int:user_id>')
@login_required
@role_required('admin')
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.username == 'admin':
        flash('Você não pode excluir o usuário admin.', 'danger')
        return redirect(url_for('list_users'))
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Usuário excluído com sucesso!', 'success')
    return redirect(url_for('list_users'))

# Rota principal: exibe os problemas cadastrados e, para validadores/admin, notifica problemas pendentes
@app.route('/')
@login_required
def index():
    user = User.query.get(session['user_id'])
    problems = Problem.query.all()
    pending_problems = []
    # Se o usuário for admin ou validador, busca problemas pendentes (não aprovados)
    if user.role in ['admin', 'validador']:
        pending_problems = Problem.query.filter_by(approved=False).all()
    return render_template('index.html', problems=problems, user_role=user.role, pending_problems=pending_problems)

# Rota para cadastrar um novo problema
@app.route('/problems', methods=['POST'])
@login_required
def create_problem():
    title = request.form.get('title')
    description = request.form.get('description')
    user = User.query.get(session['user_id'])
    new_problem = Problem(
        title=title, 
        description=description,
        created_by=user.id,
        approved=True  # padrão
    )
    # Se o usuário é espectador, o problema precisa de aprovação
    if user.role == 'espectador':
        new_problem.approved = False
        flash('Problema cadastrado, aguardando aprovação.', 'info')
    else:
        flash('Problema cadastrado com sucesso!', 'success')
    db.session.add(new_problem)
    db.session.commit()
    return redirect(url_for('index'))

# Rota para aprovar um problema pendente (apenas admin e validador)
@app.route('/approve_problem/<int:problem_id>')
@login_required
@role_required('admin', 'validador')
def approve_problem(problem_id):
    problem = Problem.query.get_or_404(problem_id)
    problem.approved = True
    db.session.commit()
    flash('Problema aprovado com sucesso!', 'success')
    return redirect(url_for('index'))

# Rota para cadastrar uma solução a um problema (apenas admin e validador)
@app.route('/problems/<int:problem_id>/solutions', methods=['POST'])
@login_required
@role_required('admin', 'validador')
def add_solution(problem_id):
    description = request.form.get('description')
    problem = Problem.query.get_or_404(problem_id)
    new_solution = Solution(description=description, problem=problem)
    db.session.add(new_solution)
    db.session.commit()
    flash('Solução adicionada com sucesso!', 'success')
    return redirect(url_for('index'))

# Rota de busca de problemas
@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    user = User.query.get(session['user_id'])
    if query:
        problems_found = Problem.query.filter(
            or_(
                Problem.title.ilike(f'%{query}%'),
                Problem.description.ilike(f'%{query}%')
            )
        ).all()
        results = []
        for problem in problems_found:
            sol_list = [sol.description for sol in problem.solutions]
            results.append({
                'problem': {
                    'id': problem.id,
                    'title': problem.title,
                    'description': problem.description,
                },
                'solutions': sol_list
            })
        return render_template('search.html', query=query, results=results, user_role=user.role)
    return render_template('search.html', query=query, results=[], user_role=user.role)

# Rotas para editar e deletar problemas/soluções (apenas admin e validador)
@app.route('/edit_problem/<int:problem_id>', methods=['POST'])
@login_required
@role_required('admin', 'validador')
def edit_problem(problem_id):
    problem = Problem.query.get_or_404(problem_id)
    problem.title = request.form['title']
    problem.description = request.form['description']
    db.session.commit()
    flash('Problema atualizado com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/delete_problem/<int:problem_id>')
@login_required
@role_required('admin', 'validador')
def delete_problem(problem_id):
    problem = Problem.query.get_or_404(problem_id)
    db.session.delete(problem)
    db.session.commit()
    flash('Problema excluído com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/edit_solution/<int:solution_id>', methods=['POST'])
@login_required
@role_required('admin', 'validador')
def edit_solution(solution_id):
    solution = Solution.query.get_or_404(solution_id)
    solution.description = request.form['description']
    db.session.commit()
    flash('Solução atualizada com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/delete_solution/<int:solution_id>')
@login_required
@role_required('admin', 'validador')
def delete_solution(solution_id):
    solution = Solution.query.get_or_404(solution_id)
    db.session.delete(solution)
    db.session.commit()
    flash('Solução excluída com sucesso!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
