import os
import sqlite3
import secrets
import datetime
import csv
import io

from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
    jsonify,
    send_file,
    abort
)

from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get(
    'DATABASE_PATH',
    os.path.join(BASE_DIR, 'instance', 'voting.db')
)

app = Flask(__name__)

app.secret_key = os.environ.get(
    'SECRET_KEY',
    'change-this-secret-key-in-production'
)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# ============================================================
# DATABASE SCHEMA
# ============================================================

SCHEMA = '''
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('voter','candidate','admin')),
    phone TEXT,
    language TEXT DEFAULT 'English',
    accessibility INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS elections(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    start_at TEXT NOT NULL,
    end_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Draft',
    created_by INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS nominations(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id INTEGER NOT NULL,
    election_id INTEGER NOT NULL,
    manifesto TEXT,
    status TEXT DEFAULT 'Pending',
    submitted_at TEXT NOT NULL,
    UNIQUE(candidate_id,election_id),
    FOREIGN KEY(candidate_id) REFERENCES users(id),
    FOREIGN KEY(election_id) REFERENCES elections(id)
);

CREATE TABLE IF NOT EXISTS votes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    voter_id INTEGER NOT NULL,
    cast_at TEXT NOT NULL,
    receipt_code TEXT UNIQUE NOT NULL,
    UNIQUE(election_id,voter_id),
    FOREIGN KEY(election_id) REFERENCES elections(id),
    FOREIGN KEY(candidate_id) REFERENCES users(id),
    FOREIGN KEY(voter_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notifications(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS feedback(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    rating INTEGER,
    category TEXT,
    message TEXT NOT NULL,
    status TEXT DEFAULT 'New',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS complaints(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT DEFAULT 'Open',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    entity TEXT,
    entity_id INTEGER,
    ip_address TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS otp_verifications(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    otp TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_resets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT
);
'''


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def now():
    return datetime.datetime.now().replace(
        microsecond=0
    ).isoformat(sep=' ')


def get_db():

    if 'db' not in g:

        os.makedirs(
            os.path.dirname(DB_PATH),
            exist_ok=True
        )

        g.db = sqlite3.connect(DB_PATH)

        g.db.row_factory = sqlite3.Row

        g.db.execute(
            'PRAGMA foreign_keys=ON'
        )

    return g.db


@app.teardown_appcontext
def close_db(exc):

    db = g.pop('db', None)

    if db:
        db.close()


def q(sql, args=(), one=False):

    cur = get_db().execute(sql, args)

    rows = cur.fetchall()

    cur.close()

    if one:
        return rows[0] if rows else None

    return rows


def exec_sql(sql, args=()):

    db = get_db()

    cur = db.execute(sql, args)

    db.commit()

    return cur.lastrowid


def audit(action, entity=None, entity_id=None):

    uid = session.get('user_id')

    ip = request.headers.get(
        'X-Forwarded-For',
        request.remote_addr
    )

    exec_sql(
        '''
        INSERT INTO audit_logs(
            user_id,
            action,
            entity,
            entity_id,
            ip_address,
            created_at
        )
        VALUES(?,?,?,?,?,?)
        ''',
        (
            uid,
            action,
            entity,
            entity_id,
            ip,
            now()
        )
    )


def notify(uid, title, msg):

    exec_sql(
        '''
        INSERT INTO notifications(
            user_id,
            title,
            message,
            created_at
        )
        VALUES(?,?,?,?)
        ''',
        (
            uid,
            title,
            msg,
            now()
        )
    )


# ============================================================
# LOGIN REQUIRED
# ============================================================

def login_required(fn):

    @wraps(fn)
    def wrap(*a, **kw):

        if not session.get('user_id'):

            flash(
                'Please login first.',
                'warning'
            )

            return redirect(
                url_for(
                    'login',
                    next=request.path
                )
            )

        return fn(*a, **kw)

    return wrap


# ============================================================
# ROLE REQUIRED
# ============================================================

def role_required(*roles):

    def deco(fn):

        @wraps(fn)
        def wrap(*a, **kw):

            if not session.get('user_id'):
                return redirect(
                    url_for('login')
                )

            if session.get('role') not in roles:
                abort(403)

            return fn(*a, **kw)

        return wrap

    return deco


# ============================================================
# COMMON TEMPLATE DATA
# ============================================================

@app.context_processor
def common():

    unread = 0

    if session.get('user_id'):

        row = q(
            '''
            SELECT COUNT(*) AS c
            FROM notifications
            WHERE user_id=? AND is_read=0
            ''',
            (session['user_id'],),
            True
        )

        unread = row['c'] if row else 0

    current_user = None

    if session.get('user_id'):

        current_user = q(
            'SELECT * FROM users WHERE id=?',
            (session['user_id'],),
            True
        )

    return {
        'unread_notifications': unread,
        'current_user': current_user
    }


# ============================================================
# PUBLIC PAGES
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/how-it-works')
def how():
    return render_template('how.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


# ============================================================
# REGISTER
# ============================================================

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        name = request.form.get(
            'name',
            ''
        ).strip()

        email = request.form.get(
            'email',
            ''
        ).strip().lower()

        phone = request.form.get(
            'phone',
            ''
        ).strip()

        pw = request.form.get(
            'password',
            ''
        )

        role = request.form.get(
            'role',
            'voter'
        )

        if role not in ('voter', 'candidate'):
            role = 'voter'

        if len(pw) < 8:

            flash(
                'Password must contain at least 8 characters.',
                'danger'
            )

            return render_template(
                'register.html'
            )

        try:

            uid = exec_sql(
                '''
                INSERT INTO users(
                    name,
                    email,
                    password_hash,
                    role,
                    phone,
                    created_at
                )
                VALUES(?,?,?,?,?,?)
                ''',
                (
                    name,
                    email,
                    generate_password_hash(pw),
                    role,
                    phone,
                    now()
                )
            )

            otp = str(
                secrets.randbelow(900000) + 100000
            )

            exp = (
                datetime.datetime.now()
                + datetime.timedelta(minutes=10)
            ).isoformat()

            exec_sql(
                '''
                INSERT INTO otp_verifications(
                    user_id,
                    otp,
                    purpose,
                    expires_at
                )
                VALUES(?,?,?,?)
                ''',
                (
                    uid,
                    otp,
                    'registration',
                    exp
                )
            )

            session['pending_user'] = uid

            audit(
                'REGISTER',
                'users',
                uid
            )

            flash(
                f'Registration successful. Demo OTP: {otp}',
                'success'
            )

            return redirect(
                url_for('verify_otp')
            )

        except sqlite3.IntegrityError:

            flash(
                'Email already registered.',
                'danger'
            )

    return render_template(
        'register.html'
    )


# ============================================================
# OTP
# ============================================================

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():

    uid = session.get('pending_user')

    if not uid:
        return redirect(
            url_for('login')
        )

    if request.method == 'POST':

        otp = request.form.get(
            'otp',
            ''
        ).strip()

        row = q(
            '''
            SELECT *
            FROM otp_verifications
            WHERE user_id=?
            AND purpose='registration'
            AND used=0
            ORDER BY id DESC
            ''',
            (uid,),
            True
        )

        if (
            row
            and row['otp'] == otp
            and datetime.datetime.fromisoformat(
                row['expires_at']
            ) >= datetime.datetime.now()
        ):

            exec_sql(
                '''
                UPDATE otp_verifications
                SET used=1
                WHERE id=?
                ''',
                (row['id'],)
            )

            session.pop(
                'pending_user',
                None
            )

            flash(
                'OTP verified. You can login now.',
                'success'
            )

            return redirect(
                url_for('login')
            )

        flash(
            'Invalid or expired OTP.',
            'danger'
        )

    return render_template(
        'verify_otp.html'
    )


# ============================================================
# LOGIN
# ============================================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form.get(
            'email',
            ''
        ).strip().lower()

        pw = request.form.get(
            'password',
            ''
        )

        user = q(
            '''
            SELECT *
            FROM users
            WHERE email=?
            AND is_active=1
            ''',
            (email,),
            True
        )

        if user and check_password_hash(
            user['password_hash'],
            pw
        ):

            session.clear()

            session['user_id'] = user['id']
            session['role'] = user['role']
            session['name'] = user['name']

            audit(
                'LOGIN',
                'users',
                user['id']
            )

            return redirect(
                url_for('dashboard')
            )

        flash(
            'Invalid email or password.',
            'danger'
        )

    return render_template(
        'login.html'
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route('/logout')
def logout():

    if session.get('user_id'):

        audit(
            'LOGOUT',
            'users',
            session['user_id']
        )

    session.clear()

    return redirect(
        url_for('index')
    )


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':

        email = request.form.get(
            'email',
            ''
        ).strip().lower()

        user = q(
            'SELECT * FROM users WHERE email=?',
            (email,),
            True
        )

        if user:

            token = secrets.token_urlsafe(24)

            exp = (
                datetime.datetime.now()
                + datetime.timedelta(minutes=30)
            ).isoformat()

            exec_sql(
                '''
                INSERT INTO password_resets(
                    user_id,
                    token,
                    expires_at
                )
                VALUES(?,?,?)
                ''',
                (
                    user['id'],
                    token,
                    exp
                )
            )

            flash(
                f'Demo reset link token: {token}',
                'info'
            )

        else:

            flash(
                'If the account exists, reset instructions have been generated.',
                'info'
            )

    return render_template(
        'forgot.html'
    )


# ============================================================
# RESET PASSWORD
# ============================================================

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    row = q(
        '''
        SELECT *
        FROM password_resets
        WHERE token=?
        AND used=0
        ''',
        (token,),
        True
    )

    if (
        not row
        or datetime.datetime.fromisoformat(
            row['expires_at']
        ) < datetime.datetime.now()
    ):

        return render_template(
            'error.html',
            code=400,
            message='Invalid or expired reset token.'
        )

    if request.method == 'POST':

        pw = request.form.get(
            'password',
            ''
        )

        if len(pw) < 8:

            flash(
                'Password must be at least 8 characters.',
                'danger'
            )

        else:

            exec_sql(
                '''
                UPDATE users
                SET password_hash=?
                WHERE id=?
                ''',
                (
                    generate_password_hash(pw),
                    row['user_id']
                )
            )

            exec_sql(
                '''
                UPDATE password_resets
                SET used=1
                WHERE id=?
                ''',
                (row['id'],)
            )

            flash(
                'Password changed successfully.',
                'success'
            )

            return redirect(
                url_for('login')
            )

    return render_template(
        'reset.html',
        token=token
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route('/dashboard')
@login_required
def dashboard():

    role = session['role']

    return redirect(
        url_for(
            {
                'voter': 'voter_dashboard',
                'candidate': 'candidate_dashboard',
                'admin': 'admin_dashboard'
            }[role]
        )
    )


# ============================================================
# VOTER DASHBOARD
# ============================================================

@app.route('/voter')
@role_required('voter')
def voter_dashboard():

    elections = q(
        '''
        SELECT *
        FROM elections
        WHERE status IN(
            'Upcoming',
            'Active',
            'Closed',
            'Result Published'
        )
        ORDER BY start_at DESC
        '''
    )

    history = q(
        '''
        SELECT
            v.*,
            e.title,
            c.name candidate_name
        FROM votes v
        JOIN elections e
            ON e.id=v.election_id
        JOIN users c
            ON c.id=v.candidate_id
        WHERE v.voter_id=?
        ORDER BY v.cast_at DESC
        ''',
        (session['user_id'],)
    )

    return render_template(
        'voter_dashboard.html',
        elections=elections,
        history=history
    )


# ============================================================
# CANDIDATE DASHBOARD
# ============================================================

@app.route('/candidate')
@role_required('candidate')
def candidate_dashboard():

    noms = q(
        '''
        SELECT
            n.*,
            e.title,
            e.status,
            e.start_at,
            e.end_at
        FROM nominations n
        JOIN elections e
            ON e.id=n.election_id
        WHERE n.candidate_id=?
        ORDER BY e.start_at DESC
        ''',
        (session['user_id'],)
    )

    return render_template(
        'candidate_dashboard.html',
        noms=noms
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route('/admin')
@role_required('admin')
def admin_dashboard():

    stats = {
        k: q(
            sql,
            (),
            True
        )['c']
        for k, sql in {
            'users':
                'SELECT COUNT(*) c FROM users',

            'elections':
                'SELECT COUNT(*) c FROM elections',

            'votes':
                'SELECT COUNT(*) c FROM votes',

            'complaints':
                "SELECT COUNT(*) c FROM complaints WHERE status!='Resolved'"
        }.items()
    }

    elections = q(
        'SELECT * FROM elections ORDER BY id DESC'
    )

    users = q(
        '''
        SELECT
            id,
            name,
            email,
            role,
            is_active,
            created_at
        FROM users
        ORDER BY id DESC
        LIMIT 100
        '''
    )

    return render_template(
        'admin_dashboard.html',
        stats=stats,
        elections=elections,
        users=users
    )


# ============================================================
# ELECTION LIST
# ============================================================

@app.route('/elections')
@login_required
def elections():

    rows = q(
        '''
        SELECT *
        FROM elections
        ORDER BY start_at DESC
        '''
    )

    return render_template(
        'elections.html',
        elections=rows
    )


# ============================================================
# ELECTION DETAILS
# ============================================================

@app.route('/election/<int:eid>')
@login_required
def election_detail(eid):

    e = q(
        'SELECT * FROM elections WHERE id=?',
        (eid,),
        True
    )

    if not e:
        abort(404)

    noms = q(
        '''
        SELECT
            n.*,
            u.name candidate_name,
            u.email
        FROM nominations n
        JOIN users u
            ON u.id=n.candidate_id
        WHERE n.election_id=?
        AND n.status='Approved'
        ORDER BY u.name
        ''',
        (eid,)
    )

    voted = None

    if session['role'] == 'voter':

        voted = q(
            '''
            SELECT id
            FROM votes
            WHERE election_id=?
            AND voter_id=?
            ''',
            (
                eid,
                session['user_id']
            ),
            True
        )

    return render_template(
        'election_detail.html',
        e=e,
        noms=noms,
        voted=voted
    )


# ============================================================
# VOTE
# ============================================================

@app.route('/vote/<int:eid>', methods=['GET', 'POST'])
@role_required('voter')
def vote(eid):

    e = q(
        'SELECT * FROM elections WHERE id=?',
        (eid,),
        True
    )

    if not e or e['status'] != 'Active':

        flash(
            'This election is not active.',
            'warning'
        )

        return redirect(
            url_for('elections')
        )

    if q(
        '''
        SELECT id
        FROM votes
        WHERE election_id=?
        AND voter_id=?
        ''',
        (
            eid,
            session['user_id']
        ),
        True
    ):

        flash(
            'You have already voted in this election.',
            'warning'
        )

        return redirect(
            url_for(
                'election_detail',
                eid=eid
            )
        )

    noms = q(
        '''
        SELECT
            n.*,
            u.name candidate_name
        FROM nominations n
        JOIN users u
            ON u.id=n.candidate_id
        WHERE n.election_id=?
        AND n.status='Approved'
        ''',
        (eid,)
    )

    if request.method == 'POST':

        cid = request.form.get(
            'candidate_id'
        )

        candidate = q(
            '''
            SELECT id
            FROM nominations
            WHERE election_id=?
            AND candidate_id=?
            AND status='Approved'
            ''',
            (
                eid,
                cid
            ),
            True
        )

        if not candidate:

            flash(
                'Invalid candidate selection.',
                'danger'
            )

            return render_template(
                'vote.html',
                e=e,
                noms=noms
            )

        receipt = secrets.token_urlsafe(12)

        try:

            vid = exec_sql(
                '''
                INSERT INTO votes(
                    election_id,
                    candidate_id,
                    voter_id,
                    cast_at,
                    receipt_code
                )
                VALUES(?,?,?,?,?)
                ''',
                (
                    eid,
                    cid,
                    session['user_id'],
                    now(),
                    receipt
                )
            )

            audit(
                'CAST_VOTE',
                'votes',
                vid
            )

            notify(
                session['user_id'],
                'Vote recorded',
                'Your vote was recorded. Receipt: ' + receipt
            )

            flash(
                'Vote submitted successfully.',
                'success'
            )

            return redirect(
                url_for(
                    'confirmation',
                    receipt=receipt
                )
            )

        except sqlite3.IntegrityError:

            flash(
                'Duplicate vote prevented.',
                'warning'
            )

            return redirect(
                url_for(
                    'election_detail',
                    eid=eid
                )
            )

    return render_template(
        'vote.html',
        e=e,
        noms=noms
    )


# ============================================================
# CONFIRMATION
# ============================================================

@app.route('/confirmation/<receipt>')
@login_required
def confirmation(receipt):

    return render_template(
        'confirmation.html',
        receipt=receipt
    )


# ============================================================
# RESULTS
# ============================================================

@app.route('/results/<int:eid>')
@login_required
def results(eid):

    e = q(
        'SELECT * FROM elections WHERE id=?',
        (eid,),
        True
    )

    if not e:
        abort(404)

    rows = q(
        '''
        SELECT
            u.name candidate_name,
            COUNT(v.id) votes
        FROM nominations n
        JOIN users u
            ON u.id=n.candidate_id
        LEFT JOIN votes v
            ON v.candidate_id=n.candidate_id
            AND v.election_id=n.election_id
        WHERE n.election_id=?
        AND n.status='Approved'
        GROUP BY n.candidate_id
        ORDER BY votes DESC
        ''',
        (eid,)
    )

    return render_template(
        'results.html',
        e=e,
        rows=rows
    )


# ============================================================
# PROFILE
# ============================================================

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():

    if request.method == 'POST':

        name = request.form.get(
            'name',
            ''
        ).strip()

        phone = request.form.get(
            'phone',
            ''
        ).strip()

        lang = request.form.get(
            'language',
            'English'
        )

        access = (
            1
            if request.form.get('accessibility')
            else 0
        )

        exec_sql(
            '''
            UPDATE users
            SET
                name=?,
                phone=?,
                language=?,
                accessibility=?
            WHERE id=?
            ''',
            (
                name,
                phone,
                lang,
                access,
                session['user_id']
            )
        )

        session['name'] = name

        audit(
            'UPDATE_PROFILE',
            'users',
            session['user_id']
        )

        flash(
            'Profile updated.',
            'success'
        )

    return render_template(
        'profile.html',
        user=q(
            'SELECT * FROM users WHERE id=?',
            (session['user_id'],),
            True
        )
    )


# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():

    user = q(
        'SELECT * FROM users WHERE id=?',
        (session['user_id'],),
        True
    )

    old = request.form.get(
        'old_password',
        ''
    )

    new = request.form.get(
        'new_password',
        ''
    )

    if not check_password_hash(
        user['password_hash'],
        old
    ):

        flash(
            'Current password is incorrect.',
            'danger'
        )

    elif len(new) < 8:

        flash(
            'New password must be at least 8 characters.',
            'danger'
        )

    else:

        exec_sql(
            '''
            UPDATE users
            SET password_hash=?
            WHERE id=?
            ''',
            (
                generate_password_hash(new),
                user['id']
            )
        )

        audit(
            'CHANGE_PASSWORD',
            'users',
            user['id']
        )

        flash(
            'Password changed.',
            'success'
        )

    return redirect(
        url_for('profile')
    )


# ============================================================
# NOTIFICATIONS
# ============================================================

@app.route('/notifications')
@login_required
def notifications():

    rows = q(
        '''
        SELECT *
        FROM notifications
        WHERE user_id=?
        ORDER BY created_at DESC
        ''',
        (session['user_id'],)
    )

    exec_sql(
        '''
        UPDATE notifications
        SET is_read=1
        WHERE user_id=?
        ''',
        (session['user_id'],)
    )

    return render_template(
        'notifications.html',
        notifications=rows
    )


# ============================================================
# FEEDBACK
# ============================================================

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():

    if request.method == 'POST':

        exec_sql(
            '''
            INSERT INTO feedback(
                user_id,
                rating,
                category,
                message,
                created_at
            )
            VALUES(?,?,?,?,?)
            ''',
            (
                session['user_id'],
                request.form.get('rating'),
                request.form.get('category'),
                request.form.get('message'),
                now()
            )
        )

        flash(
            'Feedback submitted.',
            'success'
        )

        return redirect(
            url_for('feedback')
        )

    rows = q(
        '''
        SELECT *
        FROM feedback
        WHERE user_id=?
        ORDER BY created_at DESC
        ''',
        (session['user_id'],)
    )

    return render_template(
        'feedback.html',
        rows=rows
    )


# ============================================================
# COMPLAINTS
# ============================================================

@app.route('/complaints', methods=['GET', 'POST'])
@login_required
def complaints():

    if request.method == 'POST':

        exec_sql(
            '''
            INSERT INTO complaints(
                user_id,
                subject,
                message,
                created_at
            )
            VALUES(?,?,?,?)
            ''',
            (
                session['user_id'],
                request.form.get('subject'),
                request.form.get('message'),
                now()
            )
        )

        flash(
            'Complaint submitted.',
            'success'
        )

        return redirect(
            url_for('complaints')
        )

    rows = q(
        '''
        SELECT *
        FROM complaints
        WHERE user_id=?
        ORDER BY created_at DESC
        ''',
        (session['user_id'],)
    )

    return render_template(
        'complaints.html',
        rows=rows
    )


# ============================================================
# CANDIDATE NOMINATION
# ============================================================

@app.route(
    '/candidate/nominate/<int:eid>',
    methods=['GET', 'POST']
)
@role_required('candidate')
def nominate(eid):

    e = q(
        'SELECT * FROM elections WHERE id=?',
        (eid,),
        True
    )

    if not e:
        abort(404)

    if request.method == 'POST':

        try:

            nid = exec_sql(
                '''
                INSERT INTO nominations(
                    candidate_id,
                    election_id,
                    manifesto,
                    status,
                    submitted_at
                )
                VALUES(?,?,?,?,?)
                ''',
                (
                    session['user_id'],
                    eid,
                    request.form.get('manifesto'),
                    'Pending',
                    now()
                )
            )

            audit(
                'SUBMIT_NOMINATION',
                'nominations',
                nid
            )

            flash(
                'Nomination submitted for admin approval.',
                'success'
            )

            return redirect(
                url_for('candidate_dashboard')
            )

        except sqlite3.IntegrityError:

            flash(
                'You already submitted a nomination.',
                'warning'
            )

    return render_template(
        'nominate.html',
        e=e
    )


# ============================================================
# ADMIN CREATE ELECTION
# ============================================================

@app.route(
    '/admin/election/create',
    methods=['POST']
)
@role_required('admin')
def create_election():

    title = request.form.get(
        'title'
    )

    desc = request.form.get(
        'description'
    )

    start = request.form.get(
        'start_at'
    )

    end = request.form.get(
        'end_at'
    )

    status = request.form.get(
        'status',
        'Draft'
    )

    eid = exec_sql(
        '''
        INSERT INTO elections(
            title,
            description,
            start_at,
            end_at,
            status,
            created_by,
            created_at
        )
        VALUES(?,?,?,?,?,?,?)
        ''',
        (
            title,
            desc,
            start,
            end,
            status,
            session['user_id'],
            now()
        )
    )

    audit(
        'CREATE_ELECTION',
        'elections',
        eid
    )

    flash(
        'Election created.',
        'success'
    )

    return redirect(
        url_for('admin_dashboard')
    )


# ============================================================
# UPDATE ELECTION STATUS
# ============================================================

@app.route(
    '/admin/election/<int:eid>/status',
    methods=['POST']
)
@role_required('admin')
def update_election_status(eid):

    status = request.form.get(
        'status'
    )

    allowed = {
        'Draft',
        'Upcoming',
        'Active',
        'Closed',
        'Result Published',
        'Archived'
    }

    if status not in allowed:
        abort(400)

    election = q(
        'SELECT * FROM elections WHERE id=?',
        (eid,),
        True
    )

    if not election:
        abort(404)

    exec_sql(
        '''
        UPDATE elections
        SET status=?
        WHERE id=?
        ''',
        (
            status,
            eid
        )
    )

    audit(
        'UPDATE_ELECTION_STATUS',
        'elections',
        eid
    )

    for u in q(
        '''
        SELECT id
        FROM users
        WHERE role='voter'
        AND is_active=1
        '''
    ):

        notify(
            u['id'],
            'Election status updated',
            f"Election '{election['title']}' is now {status}."
        )

    return redirect(
        url_for('admin_dashboard')
    )


# ============================================================
# DELETE ELECTION - UPDATED
# ============================================================

@app.route(
    '/admin/election/<int:eid>/delete',
    methods=['POST']
)
@role_required('admin')
def delete_election(eid):

    # --------------------------------------------------------
    # 1. Check whether election exists
    # --------------------------------------------------------

    election = q(
        '''
        SELECT *
        FROM elections
        WHERE id=?
        ''',
        (eid,),
        True
    )

    if not election:

        flash(
            'Election not found.',
            'danger'
        )

        return redirect(
            url_for('admin_dashboard')
        )

    election_title = election['title']

    # --------------------------------------------------------
    # 2. Delete votes belonging to this election
    # --------------------------------------------------------

    exec_sql(
        '''
        DELETE FROM votes
        WHERE election_id=?
        ''',
        (eid,)
    )

    # --------------------------------------------------------
    # 3. Delete nominations belonging to this election
    # --------------------------------------------------------

    exec_sql(
        '''
        DELETE FROM nominations
        WHERE election_id=?
        ''',
        (eid,)
    )

    # --------------------------------------------------------
    # 4. Delete the election itself
    # --------------------------------------------------------

    exec_sql(
        '''
        DELETE FROM elections
        WHERE id=?
        ''',
        (eid,)
    )

    # --------------------------------------------------------
    # 5. Record deletion in audit log
    # --------------------------------------------------------

    audit(
        'DELETE_ELECTION',
        'elections',
        eid
    )

    # --------------------------------------------------------
    # 6. Show success message
    # --------------------------------------------------------

    flash(
        f"Election '{election_title}' deleted successfully.",
        'success'
    )

    return redirect(
        url_for('admin_dashboard')
    )


# ============================================================
# ADMIN NOMINATIONS
# ============================================================

@app.route('/admin/nominations')
@role_required('admin')
def admin_nominations():

    rows = q(
        '''
        SELECT
            n.*,
            u.name candidate_name,
            e.title election_title
        FROM nominations n
        JOIN users u
            ON u.id=n.candidate_id
        JOIN elections e
            ON e.id=n.election_id
        ORDER BY n.id DESC
        '''
    )

    return render_template(
        'admin_nominations.html',
        rows=rows
    )


# ============================================================
# NOMINATION STATUS
# ============================================================

@app.route(
    '/admin/nomination/<int:nid>/status',
    methods=['POST']
)
@role_required('admin')
def nomination_status(nid):

    status = request.form.get(
        'status'
    )

    allowed = {
        'Pending',
        'Approved',
        'Rejected'
    }

    if status not in allowed:
        abort(400)

    exec_sql(
        '''
        UPDATE nominations
        SET status=?
        WHERE id=?
        ''',
        (
            status,
            nid
        )
    )

    row = q(
        '''
        SELECT candidate_id
        FROM nominations
        WHERE id=?
        ''',
        (nid,),
        True
    )

    if row:

        notify(
            row['candidate_id'],
            'Nomination updated',
            f'Your nomination status is now {status}.'
        )

    audit(
        'UPDATE_NOMINATION',
        'nominations',
        nid
    )

    return redirect(
        url_for('admin_nominations')
    )


# ============================================================
# ADMIN USERS
# ============================================================

@app.route('/admin/users')
@role_required('admin')
def admin_users():

    return render_template(
        'admin_users.html',
        users=q(
            'SELECT * FROM users ORDER BY id DESC'
        )
    )


# ============================================================
# TOGGLE USER
# ============================================================

@app.route(
    '/admin/user/<int:uid>/toggle',
    methods=['POST']
)
@role_required('admin')
def toggle_user(uid):

    if uid == session['user_id']:

        flash(
            'You cannot disable your own account.',
            'warning'
        )

        return redirect(
            url_for('admin_users')
        )

    u = q(
        '''
        SELECT is_active
        FROM users
        WHERE id=?
        ''',
        (uid,),
        True
    )

    if not u:
        abort(404)

    exec_sql(
        '''
        UPDATE users
        SET is_active=?
        WHERE id=?
        ''',
        (
            0 if u['is_active'] else 1,
            uid
        )
    )

    audit(
        'TOGGLE_USER',
        'users',
        uid
    )

    return redirect(
        url_for('admin_users')
    )


# ============================================================
# ADMIN FEEDBACK
# ============================================================

@app.route('/admin/feedback')
@role_required('admin')
def admin_feedback():

    return render_template(
        'admin_feedback.html',
        rows=q(
            '''
            SELECT
                f.*,
                u.name
            FROM feedback f
            LEFT JOIN users u
                ON u.id=f.user_id
            ORDER BY f.id DESC
            '''
        )
    )


# ============================================================
# ADMIN COMPLAINTS
# ============================================================

@app.route('/admin/complaints')
@role_required('admin')
def admin_complaints():

    return render_template(
        'admin_complaints.html',
        rows=q(
            '''
            SELECT
                c.*,
                u.name
            FROM complaints c
            LEFT JOIN users u
                ON u.id=c.user_id
            ORDER BY c.id DESC
            '''
        )
    )


# ============================================================
# COMPLAINT STATUS
# ============================================================

@app.route(
    '/admin/complaint/<int:cid>/status',
    methods=['POST']
)
@role_required('admin')
def complaint_status(cid):

    status = request.form.get(
        'status'
    )

    exec_sql(
        '''
        UPDATE complaints
        SET status=?
        WHERE id=?
        ''',
        (
            status,
            cid
        )
    )

    audit(
        'UPDATE_COMPLAINT',
        'complaints',
        cid
    )

    return redirect(
        url_for('admin_complaints')
    )


# ============================================================
# AUDIT LOGS
# ============================================================

@app.route('/admin/audit-logs')
@role_required('admin')
def audit_logs():

    return render_template(
        'audit_logs.html',
        rows=q(
            '''
            SELECT
                a.*,
                u.name
            FROM audit_logs a
            LEFT JOIN users u
                ON u.id=a.user_id
            ORDER BY a.id DESC
            LIMIT 500
            '''
        )
    )


# ============================================================
# REPORTS
# ============================================================

@app.route('/admin/reports')
@role_required('admin')
def reports():

    rows = q(
        '''
        SELECT
            e.title,
            e.status,
            COUNT(v.id) total_votes
        FROM elections e
        LEFT JOIN votes v
            ON v.election_id=e.id
        GROUP BY e.id
        ORDER BY e.id DESC
        '''
    )

    return render_template(
        'reports.html',
        rows=rows
    )


# ============================================================
# EXPORT CSV
# ============================================================

@app.route('/admin/export/<kind>')
@role_required('admin')
def export_csv(kind):

    allowed = {

        'users':
            '''
            SELECT
                id,
                name,
                email,
                role,
                phone,
                is_active,
                created_at
            FROM users
            ''',

        'elections':
            'SELECT * FROM elections',

        'votes':
            '''
            SELECT
                id,
                election_id,
                candidate_id,
                voter_id,
                cast_at,
                receipt_code
            FROM votes
            ''',

        'audit':
            'SELECT * FROM audit_logs'
    }

    if kind not in allowed:
        abort(404)

    rows = q(
        allowed[kind]
    )

    out = io.StringIO()

    writer = csv.writer(out)

    if rows:

        writer.writerow(
            rows[0].keys()
        )

        for row in rows:

            writer.writerow(
                tuple(row)
            )

    out.seek(0)

    return send_file(
        io.BytesIO(
            out.getvalue().encode()
        ),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'{kind}.csv'
    )


# ============================================================
# ADMIN SETTINGS
# ============================================================

@app.route(
    '/admin/settings',
    methods=['GET', 'POST']
)
@role_required('admin')
def admin_settings():

    if request.method == 'POST':

        for k, v in request.form.items():

            if k != 'csrf_placeholder':

                exec_sql(
                    '''
                    INSERT INTO settings(
                        key,
                        value
                    )
                    VALUES(?,?)
                    ON CONFLICT(key)
                    DO UPDATE SET
                        value=excluded.value
                    ''',
                    (
                        k,
                        v
                    )
                )

        flash(
            'Settings saved.',
            'success'
        )

    settings = {
        r['key']: r['value']
        for r in q(
            'SELECT * FROM settings'
        )
    }

    return render_template(
        'admin_settings.html',
        settings=settings
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(403)
def e403(e):

    return render_template(
        'error.html',
        code=403,
        message='Access denied.'
    ), 403


@app.errorhandler(404)
def e404(e):

    return render_template(
        'error.html',
        code=404,
        message='Page not found.'
    ), 404


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

@app.cli.command('init-db')
def init_command():

    init_db()

    print(
        'Database initialized.'
    )


def init_db():

    db = get_db()

    db.executescript(
        SCHEMA
    )

    if not q(
        'SELECT id FROM users LIMIT 1'
    ):

        users = [

            (
                'System Admin',
                'admin@demo.com',
                'Admin@123',
                'admin'
            ),

            (
                'Demo Voter',
                'voter@demo.com',
                'Voter@123',
                'voter'
            ),

            (
                'Aarav Kumar',
                'aarav@demo.com',
                'Candidate@123',
                'candidate'
            ),

            (
                'Priya Sharma',
                'priya@demo.com',
                'Candidate@123',
                'candidate'
            )
        ]

        for name, email, pw, role in users:

            exec_sql(
                '''
                INSERT INTO users(
                    name,
                    email,
                    password_hash,
                    role,
                    created_at
                )
                VALUES(?,?,?,?,?)
                ''',
                (
                    name,
                    email,
                    generate_password_hash(pw),
                    role,
                    now()
                )
            )

        admin = q(
            '''
            SELECT id
            FROM users
            WHERE email=?
            ''',
            ('admin@demo.com',),
            True
        )['id']

        c1 = q(
            '''
            SELECT id
            FROM users
            WHERE email=?
            ''',
            ('aarav@demo.com',),
            True
        )['id']

        c2 = q(
            '''
            SELECT id
            FROM users
            WHERE email=?
            ''',
            ('priya@demo.com',),
            True
        )['id']

        start = (
            datetime.datetime.now()
            - datetime.timedelta(hours=1)
        ).strftime(
            '%Y-%m-%d %H:%M'
        )

        end = (
            datetime.datetime.now()
            + datetime.timedelta(days=2)
        ).strftime(
            '%Y-%m-%d %H:%M'
        )

        eid = exec_sql(
            '''
            INSERT INTO elections(
                title,
                description,
                start_at,
                end_at,
                status,
                created_by,
                created_at
            )
            VALUES(?,?,?,?,?,?,?)
            ''',
            (
                'Student Council Election',
                'Election for college council.',
                start,
                end,
                'Active',
                admin,
                now()
            )
        )

        for cid in (c1, c2):

            exec_sql(
                '''
                INSERT INTO nominations(
                    candidate_id,
                    election_id,
                    manifesto,
                    status,
                    submitted_at
                )
                VALUES(?,?,?,?,?)
                ''',
                (
                    cid,
                    eid,
                    'Transparent representation and student development.',
                    'Approved',
                    now()
                )
            )

        voter = q(
            '''
            SELECT id
            FROM users
            WHERE email=?
            ''',
            ('voter@demo.com',),
            True
        )['id']

        notify(
            voter,
            'Welcome',
            'Your demo voter account is ready.'
        )

        notify(
            admin,
            'System ready',
            'Admin dashboard is ready for configuration.'
        )


# ============================================================
# START APPLICATION
# ============================================================

with app.app_context():
    init_db()


if __name__ == '__main__':
    app.run(
        debug=True
    )