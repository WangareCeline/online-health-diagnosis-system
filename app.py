from flask import Flask, render_template, request, make_response, redirect, url_for
from experta import *
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from io import BytesIO, StringIO
import logging
import os
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
import geoip2.database
from geoip2.errors import AddressNotFoundError
from flask_sqlalchemy import SQLAlchemy

# Initialize GeoIP reader 
geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')


app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load disease data
diseases_list = []
diseases_symptoms = []
symptom_map = {}
d_desc_map = {}
d_treatment_map = {}

def preprocess():
    global diseases_list, diseases_symptoms, symptom_map, d_desc_map, d_treatment_map
    
    try:
        with open("diseases.txt") as diseases:
            diseases_list = [d.strip() for d in diseases.read().split("\n") if d.strip()]
        
        for disease in diseases_list:
            # Load symptoms
            symptom_file = f"Disease symptoms/{disease}.txt"
            if os.path.exists(symptom_file):
                with open(symptom_file) as f:
                    s_list = [s.strip() for s in f.read().split("\n") if s.strip()]
                    diseases_symptoms.append(s_list)
                    symptom_map[str(s_list)] = disease
            
            # Load description
            desc_file = f"Disease descriptions/{disease}.txt"
            if os.path.exists(desc_file):
                with open(desc_file) as f:
                    d_desc_map[disease] = f.read().strip()
            else:
                d_desc_map[disease] = "No description available."
            
            # Load treatments
            treatment_file = f"Disease treatments/{disease}.txt"
            if os.path.exists(treatment_file):
                with open(treatment_file) as f:
                    d_treatment_map[disease] = f.read().strip()
            else:
                d_treatment_map[disease] = "No treatment information available."
                
    except Exception as e:
        logger.error(f"Error loading data: {str(e)}")

def get_details(disease):
    return d_desc_map.get(disease, "No description available.")

def get_treatments(disease):
    return d_treatment_map.get(disease, "No treatment information available.")

def if_not_matched(disease):
    return {
        "disease": disease,
        "description": get_details(disease),
        "treatments": get_treatments(disease),
        "matched": False
    }

# Helper: Anonymize IP (SHA-256 hash with salt)
def anonymize_ip(ip):
    salt = "YOUR_SECURE_SALT_VALUE"  # Change this to a random secure value!
    return hashlib.sha256((ip + salt).encode()).hexdigest()


@app.after_request
def log_request(response):
    if request.path.startswith('/static/'):
        return response
        
    ip = request.remote_addr
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "endpoint": request.path,
        "ip": anonymize_ip(ip),
        "location": get_city_from_ip(ip),  # New: City/country
        "user_agent": request.user_agent.string,
        "symptoms": dict(request.form) if request.path == '/diagnose' and request.method == 'POST' else None,
        "diagnosis": None
    }

    if request.path == '/diagnose' and request.method == 'POST':
        symptoms = {
            k.replace('_', ' ').title(): v.title() 
            for k, v in request.form.items()
            if k not in ['csrf_token']  # Exclude CSRF token if using Flask-WTF
        }
        log_entry["symptoms"] = symptoms

    os.makedirs("logs", exist_ok=True)
    with open("logs/access.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    return response


class WebDiagnosis(KnowledgeEngine):
    def __init__(self, symptom_map, if_not_matched, get_treatments, get_details):
        super().__init__()
        self.symptom_map = symptom_map
        self.if_not_matched = if_not_matched
        self.get_details = get_details
        self.get_treatments = get_treatments
        self.result = None
        self.symptoms = {}

    @DefFacts()
    def _initial_action(self):
        yield Fact(action="find_disease")

    # Static symptom rules
    @Rule(Fact(action="find_disease"), NOT(Fact(headache=W())), salience=4)
    def symptom_0(self):
        self.declare(Fact(headache=self.symptoms['headache']))

    @Rule(Fact(action="find_disease"), NOT(Fact(back_pain=W())), salience=1)
    def symptom_1(self):
        self.declare(Fact(back_pain=self.symptoms['back_pain']))

    @Rule(Fact(action="find_disease"), NOT(Fact(chest_pain=W())), salience=1)
    def symptom_2(self):
        self.declare(Fact(chest_pain=self.symptoms['chest_pain']))

    @Rule(Fact(action="find_disease"), NOT(Fact(cough=W())), salience=3)
    def symptom_3(self):
        self.declare(Fact(cough=self.symptoms['cough']))

    @Rule(Fact(action="find_disease"), NOT(Fact(fainting=W())), salience=1)
    def symptom_4(self):
        self.declare(Fact(fainting=self.symptoms['fainting']))

    @Rule(Fact(action="find_disease"), NOT(Fact(fatigue=W())), salience=1)
    def symptom_5(self):
        self.declare(Fact(fatigue=self.symptoms['fatigue']))

    @Rule(Fact(action="find_disease"), NOT(Fact(sunken_eyes=W())), salience=1)
    def symptom_6(self):
        self.declare(Fact(sunken_eyes=self.symptoms['sunken_eyes']))

    @Rule(Fact(action="find_disease"), NOT(Fact(low_body_temp=W())), salience=1)
    def symptom_7(self):
        self.declare(Fact(low_body_temp=self.symptoms['low_body_temp']))

    @Rule(Fact(action="find_disease"), NOT(Fact(restlessness=W())), salience=1)
    def symptom_8(self):
        self.declare(Fact(restlessness=self.symptoms['restlessness']))

    @Rule(Fact(action="find_disease"), NOT(Fact(sore_throat=W())), salience=1)
    def symptom_9(self):
        self.declare(Fact(sore_throat=self.symptoms['sore_throat']))

    @Rule(Fact(action="find_disease"), NOT(Fact(fever=W())), salience=1)
    def symptom_10(self):
        self.declare(Fact(fever=self.symptoms['fever']))

    @Rule(Fact(action="find_disease"), NOT(Fact(nausea=W())), salience=1)
    def symptom_11(self):
        self.declare(Fact(nausea=self.symptoms['nausea']))

    @Rule(Fact(action="find_disease"), NOT(Fact(blurred_vision=W())), salience=1)
    def symptom_12(self):
        self.declare(Fact(blurred_vision=self.symptoms['blurred_vision']))

    # Original Disease Rules
    @Rule(
        Fact(action="find_disease"),
        Fact(headache="no"),
        Fact(back_pain="no"),
        Fact(chest_pain="no"),
        Fact(cough="no"),
        Fact(fainting="no"),
        Fact(sore_throat="no"),
        Fact(fatigue="high"),
        Fact(restlessness="no"),
        Fact(low_body_temp="no"),
        Fact(fever="low"),
        Fact(sunken_eyes="no"),
        Fact(nausea="high"),
        Fact(blurred_vision="no"),
    )
    def disease_0(self):
        self.declare(Fact(disease="Jaundice"))

    @Rule(
        Fact(action="find_disease"),
        Fact(headache="no"),
        Fact(back_pain="no"),
        Fact(chest_pain="no"),
        Fact(cough="no"),
        Fact(fainting="no"),
        Fact(sore_throat="no"),
        Fact(fatigue="no"),
        Fact(restlessness="high"),
        Fact(low_body_temp="no"),
        Fact(fever="no"),
        Fact(sunken_eyes="no"),
        Fact(nausea="no"),
        Fact(blurred_vision="no"),
    )
    def disease_1(self):
        self.declare(Fact(disease="Alzheimers"))

    @Rule(
        Fact(action="find_disease"),
        Fact(headache="no"),
        Fact(back_pain="high"),
        Fact(chest_pain="no"),
        Fact(cough="no"),
        Fact(fainting="no"),
        Fact(sore_throat="no"),
        Fact(fatigue="low"),
        Fact(restlessness="no"),
        Fact(low_body_temp="no"),
        Fact(fever="no"),
        Fact(sunken_eyes="no"),
        Fact(nausea="no"),
        Fact(blurred_vision="no"),
    )
    def disease_2(self):
        self.declare(Fact(disease="Arthritis"))

    @Rule(Fact(action="find_disease"), Fact(disease=MATCH.disease), salience=-998)
    def disease(self, disease):
        self.result = {
            "disease": disease,
            "description": self.get_details(disease),
            "treatments": self.get_treatments(disease),
            "matched": True
        }

    @Rule(
        Fact(action="find_disease"),
        Fact(headache=MATCH.headache),
        Fact(back_pain=MATCH.back_pain),
        Fact(chest_pain=MATCH.chest_pain),
        Fact(cough=MATCH.cough),
        Fact(fainting=MATCH.fainting),
        Fact(sore_throat=MATCH.sore_throat),
        Fact(fatigue=MATCH.fatigue),
        Fact(restlessness=MATCH.restlessness),
        Fact(low_body_temp=MATCH.low_body_temp),
        Fact(fever=MATCH.fever),
        Fact(sunken_eyes=MATCH.sunken_eyes),
        Fact(nausea=MATCH.nausea),
        Fact(blurred_vision=MATCH.blurred_vision),
        NOT(Fact(disease=MATCH.disease)),
        salience=-999
    )
    def not_matched(self, **symptoms):
        max_count = 0
        max_disease = ""
        lis = list(symptoms.values())
        
        for key, val in self.symptom_map.items():
            count = 0
            temp_list = eval(key)
            for j in range(0, len(lis)):
                if temp_list[j] == lis[j] and (lis[j] in ["high", "low", "yes"]):
                    count += 1
            if count > max_count:
                max_count = count
                max_disease = val
        
        if max_disease:
            self.result = self.if_not_matched(max_disease)
        else:
            self.result = {
                "disease": "Unknown",
                "description": "No matching disease found based on your symptoms.",
                "treatments": "Please consult a healthcare professional for accurate diagnosis.",
                "matched": False
            }

def generate_pdf(result):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "", 12)
        
        def clean_text(text):
            if not isinstance(text, str):
                text = str(text)
            return text.encode('ascii', 'replace').decode('ascii')

        # Title
        pdf.set_font("helvetica", 'B', 16)
        pdf.cell(200, 10, text=clean_text("Medical Diagnosis Report"), new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.ln(10)
        
        # Diagnosis
        pdf.set_font("helvetica", 'B', 14)
        pdf.cell(200, 10, text=clean_text(f"Diagnosis: {result['disease']}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 12)
        match_type = "Exact match" if result['matched'] else "Probable match"
        pdf.cell(200, 10, text=clean_text(f"Match Type: {match_type}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # Description
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(200, 10, text=clean_text("Description:"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 12)
        pdf.multi_cell(0, 10, text=clean_text(result['description']))
        pdf.ln(5)
        
        # Treatments
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(200, 10, text=clean_text("Recommended Treatments:"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 12)
        pdf.multi_cell(0, 10, text=clean_text(result['treatments']))
        pdf.ln(10)
        
        # Disclaimer
        pdf.set_font("helvetica", 'I', 10)
        pdf.multi_cell(0, 10, text=clean_text(
            "Disclaimer: This report is generated by an expert system for informational purposes only. "
            "It is not a substitute for professional medical advice, diagnosis, or treatment."
        ))
        
        # Get PDF bytes - handle both string and bytearray returns
        pdf_output = pdf.output()
        if isinstance(pdf_output, str):
            return pdf_output.encode('latin-1')
        elif isinstance(pdf_output, bytearray):
            return bytes(pdf_output)
        return pdf_output
    
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}")
        # Fallback error PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=12)
        pdf.cell(0, 10, text="Error generating report", new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 10, text=str(e))
        pdf_output = pdf.output()
        if isinstance(pdf_output, str):
            return pdf_output.encode('latin-1')
        elif isinstance(pdf_output, bytearray):
            return bytes(pdf_output)
        return pdf_output


# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diagnosis.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Diagnosis Model
class Diagnosis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_hash = db.Column(db.String(64))
    location = db.Column(db.String(100))
    user_agent = db.Column(db.String(200))
    disease = db.Column(db.String(100))
    description = db.Column(db.Text)
    treatments = db.Column(db.Text)
    matched = db.Column(db.Boolean)
    symptoms = db.Column(db.JSON)  # Stores symptoms as JSON

    def __repr__(self):
        return f'<Diagnosis {self.id} - {self.disease}>'


# ===== ADMIN AUTHENTICATION =====
ADMIN_USERNAME = "admin"  # Change these!
ADMIN_PASSWORD = "securepassword123"  # Use environment variables in production

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == ADMIN_USERNAME and auth.password == ADMIN_PASSWORD):
            return authenticate()
        return f(*args, **kwargs)
    return decorated_function

def authenticate():
    return (
        'Please login to access the admin dashboard',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

# ===== ADMIN DASHBOARD ROUTES =====
@app.route('/admin')
@admin_required
def admin_dashboard():
    date_from = request.args.get('from', (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'))
    date_to = request.args.get('to', datetime.now().strftime('%Y-%m-%d'))
    
    log_data = load_log_data(date_from, date_to)
    stats = calculate_stats(log_data)
    
    return render_template('admin/dashboard.html', 
                         stats=stats,
                         date_from=date_from,
                         date_to=date_to,
                         now=datetime.now(),
                         timedelta=timedelta)



# ===== ENHANCED ADMIN ROUTES =====
@app.route('/admin/stats')
@admin_required
def admin_stats():
    date_from = request.args.get('from', (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'))
    date_to = request.args.get('to', datetime.now().strftime('%Y-%m-%d'))
    
    log_data = load_log_data(date_from, date_to)
    stats = calculate_stats(log_data)
    
    return render_template('admin/dashboard.html', 
                         stats=stats,
                         date_from=date_from,
                         date_to=date_to)

def calculate_stats(log_data):
    stats = {
        'total_requests': len(log_data),
        'exact_matches': 0,
        'location_stats': defaultdict(int),
        'diagnosis_stats': defaultdict(int),
        'diagnosis_cases': []
    }

    for entry in log_data:
        if entry.get("diagnosis"):
            # Count exact matches
            if entry["diagnosis"].get("matched"):
                stats['exact_matches'] += 1
            
            # Track locations
            stats['location_stats'][entry.get("location", "Unknown")] += 1
            
            # Track diagnoses
            disease = entry["diagnosis"].get("disease", "Unknown")
            stats['diagnosis_stats'][disease] += 1
            
            # Prepare case details for table
            stats['diagnosis_cases'].append({
                "time": entry["timestamp"],
                "location": entry.get("location", "Unknown"),
                "symptoms": entry.get("symptoms", {}),
                "diagnosis": entry["diagnosis"]
            })
    
    # Sort cases by newest first
    stats['diagnosis_cases'].sort(key=lambda x: x['time'], reverse=True)
    
    # Limit to 100 most recent cases
    stats['diagnosis_cases'] = stats['diagnosis_cases'][:100]
    
    return stats


def load_log_data(date_from=None, date_to=None):
    log_data = []
    log_file = 'logs/access.log'
    
    try:
        if date_from:
            date_from = datetime.strptime(date_from, '%Y-%m-%d')
        if date_to:
            date_to = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
    except ValueError:
        date_from = date_to = None
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    entry_date = datetime.fromisoformat(entry['timestamp'])
                    
                    if date_from and entry_date < date_from:
                        continue
                    if date_to and entry_date > date_to:
                        continue
                        
                    log_data.append(entry)
                except json.JSONDecodeError:
                    continue
    
    return log_data


def get_city_from_ip(ip):
    try:
        if ip.startswith(('127.', '192.168.', '10.')):
            return "Local Network"
        response = geoip_reader.city(ip)
        return f"{response.city.name}, {response.country.name}" if response.city.name else response.country.name
    except AddressNotFoundError:
        return "Unknown Location"
    except Exception as e:
        logger.error(f"GeoIP error: {str(e)}")
        return "Location Error"


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/diagnose', methods=['POST'])
def diagnose():
    try:
        symptoms = {
            'headache': request.form.get('headache', 'no').lower().strip(),
            'back_pain': request.form.get('back_pain', 'no').lower().strip(),
            'chest_pain': request.form.get('chest_pain', 'no').lower().strip(),
            'cough': request.form.get('cough', 'no').lower().strip(),
            'fainting': request.form.get('fainting', 'no').lower().strip(),
            'sore_throat': request.form.get('sore_throat', 'no').lower().strip(),
            'fatigue': request.form.get('fatigue', 'no').lower().strip(),
            'restlessness': request.form.get('restlessness', 'no').lower().strip(),
            'low_body_temp': request.form.get('low_body_temp', 'no').lower().strip(),
            'fever': request.form.get('fever', 'no').lower().strip(),
            'sunken_eyes': request.form.get('sunken_eyes', 'no').lower().strip(),
            'nausea': request.form.get('nausea', 'no').lower().strip(),
            'blurred_vision': request.form.get('blurred_vision', 'no').lower().strip()
        }
        
        engine = WebDiagnosis(symptom_map, if_not_matched, get_treatments, get_details)
        engine.reset()
        engine.symptoms = symptoms
        engine.run()
        
        if not engine.result:
            engine.result = {
                "disease": "Unknown",
                "description": "No matching disease found based on your symptoms.",
                "treatments": "Please consult a healthcare professional.",
                "matched": False
            }
            
        # Save to database
        ip = request.remote_addr
        new_diagnosis = Diagnosis(
            ip_hash=anonymize_ip(ip),
            location=get_city_from_ip(ip),
            user_agent=request.user_agent.string,
            disease=engine.result['disease'],
            description=engine.result['description'],
            treatments=engine.result['treatments'],
            matched=engine.result['matched'],
            symptoms={k.replace('_', ' ').title(): v.title() for k, v in symptoms.items()}
        )
        db.session.add(new_diagnosis)
        db.session.commit()
            
        # Explicitly log the diagnosis
        ip = request.remote_addr
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "endpoint": request.path,
            "ip": anonymize_ip(ip),
            "location": get_city_from_ip(ip),
            "user_agent": request.user_agent.string,
            "symptoms": {k.replace('_', ' ').title(): v.title() for k, v in symptoms.items()},
            "diagnosis": engine.result
        }
        
        os.makedirs("logs", exist_ok=True)
        with open("logs/access.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            logger.info(f"Logged diagnosis: {engine.result['disease']}")

        return render_template('diagnosis.html', result=engine.result)
        
    except Exception as e:
        logger.error(f"Diagnosis error: {str(e)}", exc_info=True)
        return render_template('diagnosis.html', result={
            "disease": "System Error",
            "description": "An error occurred during diagnosis.",
            "treatments": "Please try again or contact support.",
            "matched": False
        })

@app.route('/download-report', methods=['POST'])
def download_report():
    try:
        result = {
            'disease': request.form.get('disease', 'Unknown'),
            'description': request.form.get('description', 'No description available.'),
            'treatments': request.form.get('treatments', 'No treatment information available.'),
            'matched': request.form.get('matched', 'False') == 'True'
        }
        
        format_type = request.form.get('format', 'pdf')
        
        if format_type == 'pdf':
            pdf_data = generate_pdf(result)
            response = make_response(pdf_data)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=diagnosis_report_{result["disease"]}.pdf'
            return response
        else:
            text_content = f"""Medical Diagnosis Report
=========================

Diagnosis: {result['disease']}
Match Type: {'Exact match' if result['matched'] else 'Probable match'}

Description:
{result['description']}

Recommended Treatments:
{result['treatments']}

Disclaimer: This report is generated by an expert system for informational purposes only. 
It is not a substitute for professional medical advice, diagnosis, or treatment.
"""
            response = make_response(text_content)
            response.headers['Content-Type'] = 'text/plain'
            response.headers['Content-Disposition'] = f'attachment; filename=diagnosis_report_{result["disease"]}.txt'
            return response
            
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}", exc_info=True)
        return "Error generating report", 500


if __name__ == '__main__':
    # Create required directories if they don't exist
    os.makedirs("Disease symptoms", exist_ok=True)
    os.makedirs("Disease descriptions", exist_ok=True)
    os.makedirs("Disease treatments", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    
    # Initialize database
    with app.app_context():
        db.create_all()
    
    preprocess()
    app.run(debug=True)