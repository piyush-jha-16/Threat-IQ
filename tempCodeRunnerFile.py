# app.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import PyPDF2
import pythoncom
import win32com.client
import hashlib
import requests
import json
from werkzeug.utils import secure_filename
import tempfile
import threading

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt'}

# VirusTotal API (You'll need to get your own API key)
VIRUSTOTAL_API_KEY = 'a64eeb902a2a81c1a31f565892357d6f1bcd929d2c77d66dde90046c2fc059db'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of the file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_pdf_links(file_path):
    """Extract links and text from PDF files"""
    links = []
    text_content = ""
    
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text_content += page.extract_text()
                
                # Extract annotations (links)
                if '/Annots' in page:
                    annotations = page['/Annots']
                    for annotation in annotations:
                        annot_obj = annotation.get_object()
                        if '/A' in annot_obj:
                            action = annot_obj['/A']
                            if '/URI' in action:
                                uri = action['/URI']
                                links.append(str(uri))
    except Exception as e:
        print(f"Error reading PDF: {e}")
    
    return links, text_content

def extract_office_metadata(file_path, file_extension):
    """Extract metadata from Office documents"""
    metadata = {}
    
    try:
        if file_extension in ['docx', 'xlsx', 'pptx']:
            # For modern Office formats, we can use python-docx, openpyxl, etc.
            # This is a simplified version - you'd need to implement proper extraction
            metadata['file_type'] = file_extension.upper()
            metadata['size'] = os.path.getsize(file_path)
            
    except Exception as e:
        print(f"Error extracting Office metadata: {e}")
    
    return metadata

def check_virustotal(file_hash):
    """Check file hash against VirusTotal"""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'YOUR_VIRUSTOTAL_API_KEY':
        return {'detected': False, 'message': 'VirusTotal API key not configured'}
    
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {'detected': False, 'message': 'VirusTotal API error'}
    except Exception as e:
        return {'detected': False, 'message': f'VirusTotal check failed: {str(e)}'}

def analyze_urls(urls):
    """Analyze extracted URLs for threats"""
    threats = []
    safe_urls = []
    
    for url in urls:
        # Basic URL analysis
        threat_level = 'safe'
        reasons = []
        
        # Check for suspicious patterns
        if any(suspicious in url.lower() for suspicious in ['bit.ly', 'tinyurl', 'phishing', 'malware']):
            threat_level = 'suspicious'
            reasons.append('Suspicious URL shortening service')
        
        if 'http://' in url.lower() and not 'https://' in url.lower():
            threat_level = 'suspicious'
            reasons.append('Uses HTTP instead of HTTPS')
            
        if threat_level == 'safe':
            safe_urls.append(url)
        else:
            threats.append({
                'url': url,
                'threat_level': threat_level,
                'reasons': reasons
            })
    
    return threats, safe_urls

def calculate_threat_score(analysis_results):
    """Calculate overall threat score based on analysis results"""
    score = 0
    max_score = 100
    
    # Weight factors for different threat types
    weights = {
        'malicious_hash': 70,
        'suspicious_urls': 20,
        'suspicious_content': 10
    }
    
    # Check for malicious hash
    if analysis_results.get('virustotal_results', {}).get('positives', 0) > 0:
        positives = analysis_results['virustotal_results']['positives']
        total = analysis_results['virustotal_results'].get('total', 1)
        hash_score = (positives / total) * weights['malicious_hash']
        score += min(hash_score, weights['malicious_hash'])
    
    # Check for suspicious URLs
    suspicious_urls_count = len(analysis_results.get('suspicious_urls', []))
    if suspicious_urls_count > 0:
        url_score = min(suspicious_urls_count * 5, weights['suspicious_urls'])
        score += url_score
    
    # Check for suspicious content
    suspicious_content = analysis_results.get('suspicious_content', [])
    if suspicious_content:
        content_score = min(len(suspicious_content) * 2, weights['suspicious_content'])
        score += content_score
    
    return min(score, max_score)

@app.route('/')
def index():
    return jsonify({"message": "Threat-IQ API is running"})

@app.route('/api/analyze/document', methods=['POST'])
def analyze_document():
    """Main endpoint for document analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # Save uploaded file temporarily
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Analyze the document
            analysis_results = analyze_document_file(file_path, filename)
            
            # Clean up temporary file
            os.remove(file_path)
            
            return jsonify(analysis_results)
            
        except Exception as e:
            return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    
    return jsonify({'error': 'Invalid file type'}), 400

def analyze_document_file(file_path, filename):
    """Core document analysis logic"""
    file_extension = filename.rsplit('.', 1)[1].lower()
    analysis_results = {
        'filename': filename,
        'file_type': file_extension.upper(),
        'file_size': os.path.getsize(file_path),
        'threat_score': 0,
        'risk_level': 'low',
        'analysis_details': {},
        'suspicious_urls': [],
        'safe_urls': [],
        'virustotal_results': {},
        'suspicious_content': []
    }
    
    # Calculate file hash
    file_hash = calculate_file_hash(file_path)
    analysis_results['file_hash'] = file_hash
    
    # Check VirusTotal
    vt_results = check_virustotal(file_hash)
    analysis_results['virustotal_results'] = vt_results
    
    # Extract content based on file type
    if file_extension == 'pdf':
        links, text_content = extract_pdf_links(file_path)
        analysis_results['extracted_links'] = links
        analysis_results['text_content'] = text_content[:1000]  # First 1000 chars
        
        # Analyze URLs
        suspicious_urls, safe_urls = analyze_urls(links)
        analysis_results['suspicious_urls'] = suspicious_urls
        analysis_results['safe_urls'] = safe_urls
        
    elif file_extension in ['docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt']:
        metadata = extract_office_metadata(file_path, file_extension)
        analysis_results['metadata'] = metadata
    
    # Calculate threat score
    threat_score = calculate_threat_score(analysis_results)
    analysis_results['threat_score'] = threat_score
    
    # Determine risk level
    if threat_score >= 70:
        analysis_results['risk_level'] = 'high'
    elif threat_score >= 30:
        analysis_results['risk_level'] = 'medium'
    else:
        analysis_results['risk_level'] = 'low'
    
    # Generate detailed analysis
    analysis_results['analysis_details'] = generate_analysis_details(analysis_results)
    
    return analysis_results

def generate_analysis_details(results):
    """Generate human-readable analysis details"""
    details = []
    
    # Hash analysis
    if results['virustotal_results'].get('positives', 0) > 0:
        positives = results['virustotal_results']['positives']
        total = results['virustotal_results'].get('total', 1)
        details.append(f"File detected as malicious by {positives}/{total} antivirus engines")
    else:
        details.append("No antivirus detections found")
    
    # URL analysis
    suspicious_url_count = len(results.get('suspicious_urls', []))
    if suspicious_url_count > 0:
        details.append(f"Found {suspicious_url_count} suspicious URLs")
    else:
        details.append("No suspicious URLs detected")
    
    # File type analysis
    details.append(f"File type: {results['file_type']}")
    details.append(f"File size: {results['file_size']} bytes")
    
    return details

if __name__ == '__main__':
    app.run(debug=True, port=5000)