# Online Voting System – Full Project

A complete Flask-based college/mini-club online voting system expanded from the earlier demo.

## Included modules
- Welcome, About, Contact, How It Works
- Voter and Candidate registration
- OTP verification (demo OTP is displayed; replace with SMS/email provider in production)
- Login, logout, password reset
- Role-based Voter / Candidate / Admin dashboards
- Election lifecycle: Draft → Upcoming → Active → Closed → Result Published → Archived
- Candidate nominations and admin approval/rejection
- One-vote-per-election enforcement
- Vote receipt confirmation
- Aggregate results and simple analytics
- Notifications
- Feedback and complaints
- Profile, language and accessibility preference
- Admin user management
- Admin election management
- Audit logs
- CSV reports
- Admin settings
- Responsive UI

## Demo accounts
- Admin: `admin@demo.com` / `Admin@123`
- Voter: `voter@demo.com` / `Voter@123`
- Candidate: `aarav@demo.com` / `Candidate@123`
- Candidate: `priya@demo.com` / `Candidate@123`

## Run in VS Code / Windows
```bat
cd D:\Surendra_projects\Online_voting_System
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

If an older `voting.db` exists and you want the new demo seed, delete `instance\voting.db` once and run again.

## Project structure
```
online_voting_full/
├── app.py
├── requirements.txt
├── README.md
├── instance/
│   └── voting.db              # generated automatically
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── about.html
│   ├── how.html
│   ├── contact.html
│   ├── register.html
│   ├── verify_otp.html
│   ├── login.html
│   ├── forgot.html
│   ├── reset.html
│   ├── voter_dashboard.html
│   ├── candidate_dashboard.html
│   ├── admin_dashboard.html
│   ├── elections.html
│   ├── election_detail.html
│   ├── vote.html
│   ├── confirmation.html
│   ├── results.html
│   ├── profile.html
│   ├── notifications.html
│   ├── feedback.html
│   ├── complaints.html
│   ├── nominate.html
│   ├── admin_nominations.html
│   ├── admin_users.html
│   ├── admin_feedback.html
│   ├── admin_complaints.html
│   ├── audit_logs.html
│   ├── reports.html
│   ├── admin_settings.html
│   └── error.html
└── static/
    ├── css/style.css
    └── js/app.js
```

## Security notes for real deployment
This is a college project implementation, not a certified public-election platform. Before production use, add HTTPS, CSRF protection on every state-changing form, secure secret management, email/SMS OTP delivery, rate limiting, stronger session/cookie settings, server-side validation, MySQL/PostgreSQL, encrypted backups, access reviews, monitoring, penetration testing and an independently reviewed ballot-secrecy design.

## UI Update
The project pages have been reformatted into readable, structured HTML/Jinja files.
Logged-in users now get a responsive left-side dashboard navigation with role-based sections
for voter, candidate, and administrator accounts. The sidebar collapses on smaller screens.
