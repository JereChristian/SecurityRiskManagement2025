from flask import Flask, render_template, request, redirect, url_for, session
from firebase_admin import auth, firestore
from firebase_init import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from pymisp import PyMISP

app = Flask(__name__)
app.secret_key = "your_secret_key"

# MISP Configuration
MISP_URL = "https://172.20.10.2"
MISP_API_KEY = "d9PMltdN0rb2sw2hy3yEXaBfN7kHU08W2HdKniPQ"
MISP_VERIFY_CERT = False  # Set to True if using a valid SSL certificate

misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_CERT)

# ============================ AUTHENTICATION ROUTES ============================

@app.route('/misp_events')
def misp_events():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch MISP events
    try:
        events = misp.search(controller='events', return_format='json')
        return render_template('misp_events.html', events=events)
    except Exception as e:
        return f"An error occurred while fetching MISP events: {str(e)}"

@app.route('/')
def home():
    return redirect(url_for('login'))  # Always send users to the login page first

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        department = request.form['department']

        try:
            # Check if user exists in Firestore
            users_ref = db.collection('users').where('username', '==', username).stream()
            if any(users_ref):
                return "Username already taken!"

            # Create a new user in Firebase Authentication
            user = auth.create_user(
                email=username,
                password=password
            )

            # Assign first user as 'admin'
            users_count = len(list(db.collection('users').stream()))
            role = 'admin' if users_count == 0 else 'user'

            # Add user to Firestore
            user_data = {
                'username': username,
                'password': generate_password_hash(password),  # Hash the password
                'roles': role,
                'department': department
            }
            db.collection('users').document(user.uid).set(user_data)

            return redirect(url_for('login'))
        except auth.EmailAlreadyExistsError:
            return "Email already exists!"
        except Exception as e:
            return f"An error occurred: {str(e)}"

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # Verify user with Firebase Authentication
            user = auth.get_user_by_email(username)

            # Retrieve user data from Firestore
            user_ref = db.collection('users').document(user.uid).get()
            if user_ref.exists:
                user_data = user_ref.to_dict()

                # Verify password
                if check_password_hash(user_data['password'], password):
                    session['username'] = user_data['username']
                    session['role'] = user_data['roles']
                    session['department'] = user_data['department']
                    session['user_id'] = user.uid  # Store user ID in session
                    return redirect(url_for('dashboard'))
                else:
                    return "Invalid credentials!"
            else:
                return "User not found!"
        except auth.UserNotFoundError:
            return "Invalid credentials!"
        except Exception as e:
            return f"An error occurred: {str(e)}"

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ============================ DASHBOARD ROUTES ============================

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Fetch all users from Firestore
    users_ref = db.collection('users').stream()
    users_data = [{'id': user.id, **user.to_dict()} for user in users_ref]

    return render_template('admin_dashboard.html', users_data=users_data)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    risk_assessments = db.collection('risk_assessments').where('user_id', '==', session['user_id']).stream()
    risk_data = [{'id': doc.id, **doc.to_dict()} for doc in risk_assessments]

    # ✅ NEW: Calculate progress
    completed_phases = {doc['phase'] for doc in risk_data}  # Get phases the user has completed
    total_phases = 4  # Total phases in the assessment
    progress = (len(completed_phases) / total_phases) * 100  # Calculate percentage
    missing_phases = [p for p in range(1, total_phases + 1) if p not in completed_phases]  # Find missing phases

    return render_template('dashboard.html', risk_data=risk_data, progress=progress, missing_phases=missing_phases)


@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        # Delete the user from Firestore
        db.collection('users').document(user_id).delete()
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        return f"An error occurred: {str(e)}"

# ============================ PHASE ROUTES ============================

@app.route('/phase_1', methods=['GET', 'POST'])
def phase_1():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Save Phase 1 data to Firestore
        phase_1_data = {
            'user_id': session['user_id'],
            'confidentiality': request.form['confidentiality'],
            'integrity': request.form['integrity'],
            'availability': request.form['availability'],
            'priority_impact': request.form['priority_impact'],
            'phase': 1
        }
        db.collection('risk_assessments').add(phase_1_data)

        return redirect(url_for('phase_2'))

    # Pass an empty dictionary as 'data' to avoid the UndefinedError
    return render_template('phase_1.html', data={})

@app.route('/phase_2', methods=['GET', 'POST'])
def phase_2():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Retrieve all form fields
        name = request.form.get('name')
        description = request.form.get('description')
        owner = request.form.get('owner')
        security_requirement = request.form.get('security_requirement')

        # Validate that all fields are present
        if not all([name, description, owner, security_requirement]):
            return "All fields are required!", 400

        # Save Phase 2 data to Firestore
        phase_2_data = {
            'user_id': session['user_id'],
            'name': name,
            'description': description,
            'owner': owner,
            'security_requirement': security_requirement,
            'phase': 2
        }
        db.collection('risk_assessments').add(phase_2_data)

        return redirect(url_for('phase_3'))

    # Render the Phase 2 template
    return render_template('phase_2.html')

@app.route('/phase_3', methods=['GET', 'POST'])
def phase_3():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Retrieve all form fields
        concern = request.form.get('concern')
        actor = request.form.get('actor')
        objective = request.form.get('objective')
        motive = request.form.get('motive')
        result = request.form.get('result')
        security = request.form.get('security')
        likelihood = request.form.get('likelihood')

        # Validate that all fields are present
        if not all([concern, actor, objective, motive, result, security, likelihood]):
            return "All fields are required!", 400

        # Save Phase 3 data to Firestore
        phase_3_data = {
            'user_id': session['user_id'],
            'concern': concern,
            'actor': actor,
            'objective': objective,
            'motive': motive,
            'result': result,
            'security': security,
            'likelihood': likelihood,
            'phase': 3
        }
        db.collection('risk_assessments').add(phase_3_data)

        return redirect(url_for('phase_4'))

    # Render the Phase 3 template
    return render_template('phase_3.html')

@app.route('/phase_4', methods=['GET', 'POST'])
def phase_4():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Retrieve all form fields
        risk_description = request.form.get('risk_description')
        financial_impact = request.form.get('financial_impact')  # Now expected to be in a 1-10 scale
        reputation_damage = request.form.get('reputation_damage')
        operational_impact = request.form.get('operational_impact')
        legal_impact = request.form.get('legal_impact')
        risk_response = request.form.get('risk_response')
        mitigation_strategy = request.form.get('mitigation_strategy')

        # Validate that all fields are present
        if not all([risk_description, financial_impact, reputation_damage, operational_impact, legal_impact, risk_response, mitigation_strategy]):
            return "All fields are required!", 400

        try:
            financial_impact = int(financial_impact)
            if financial_impact < 1 or financial_impact > 10:
                return "Financial impact must be between 1 and 10.", 400
        except ValueError:
            return "Invalid financial impact value.", 400

        # Dynamically set threat level based on financial impact scale (1-10)
        if financial_impact >= 8:  # High financial impact
            threat_level_id = "1"  # High threat level
        elif financial_impact >= 5:  # Medium financial impact
            threat_level_id = "2"  # Medium threat level
        else:  # Low financial impact
            threat_level_id = "3"  # Low threat level

        # Save Phase 4 data to Firestore
        phase_4_data = {
            'user_id': session['user_id'],
            'risk_description': risk_description,
            'financial_impact': financial_impact,
            'reputation_damage': reputation_damage,
            'operational_impact': operational_impact,
            'legal_impact': legal_impact,
            'risk_response': risk_response,
            'mitigation_strategy': mitigation_strategy,
            'phase': 4
        }
        db.collection('risk_assessments').add(phase_4_data)

        # Push risk data to MISP
        misp_event = {
            "info": f"Risk Assessment: {risk_description}",
            "threat_level_id": threat_level_id,  # Dynamic threat level
            "analysis": "1",  # Initial analysis
            "distribution": "0",  # Your organization only
            "Attribute": [
                {
                    "type": "text",
                    "category": "Financial impact",
                    "value": financial_impact
                },
                {
                    "type": "text",
                    "category": "Reputation damage",
                    "value": reputation_damage
                }
            ]
        }
        misp.add_event(misp_event)

        return redirect(url_for('dashboard'))

    return render_template('phase_4.html')

# ============================ DELETE ROUTE ============================

@app.route('/delete_phase/<doc_id>', methods=['POST'])
def delete_phase(doc_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Delete the document from Firestore
        db.collection('risk_assessments').document(doc_id).delete()
        return redirect(url_for('dashboard'))
    except Exception as e:
        return f"An error occurred: {str(e)}"

# Run the application
if __name__ == '__main__':
    app.run(debug=True)