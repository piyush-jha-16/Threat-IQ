from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import PyPDF2
import hashlib
import requests
import json
from werkzeug.utils import secure_filename
import tempfile
import re
import math
from datetime import datetime
import zipfile
import olefile
import struct

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

def extract_pdf_links_and_text(file_path):
    """Extract links and text from PDF files with improved detection"""
    links = []
    text_content = ""
    
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                page_text = page.extract_text()
                text_content += page_text
                
                # Extract URLs from text using regex (more comprehensive)
                url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
                text_urls = re.findall(url_pattern, page_text)
                links.extend(text_urls)
                
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
    
    # Remove duplicates
    links = list(set(links))
    return links, text_content

def is_internal_office_url(url):
    """Check if URL is an internal Office XML reference or namespace"""
    internal_patterns = [
        r'^http://schemas\.microsoft\.com/',
        r'^http://schemas\.openxmlformats\.org/',
        r'^http://purl\.org/',
        r'^http://www\.w3\.org/',
        r'^mailto:',
        r'^ftp:',
        r'^file:',
        r'^javascript:',
        r'^vbscript:',
        r'^\#',  # Internal anchors
        r'^\./',  # Relative paths
        r'^http://localhost',
        r'^http://127\.0\.0\.1',
    ]
    
    url_lower = url.lower()
    
    # Check for XML namespaces and internal references
    if any(re.match(pattern, url_lower) for pattern in internal_patterns):
        return True
    
    # Check for UUID-like patterns common in Office XML
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', url_lower):
        return True
    
    # Check for internal relationship IDs
    if re.match(r'^rId\d+', url_lower):
        return True
    
    return False

def clean_and_filter_urls(urls):
    """Clean URLs and filter out internal/technical ones"""
    cleaned_urls = []
    
    for url in urls:
        # Remove common XML artifacts and clean the URL
        clean_url = url.strip()
        
        # Remove common prefixes/suffixes from Office XML
        clean_url = re.sub(r'^[xX][mM][lL]:', '', clean_url)
        clean_url = re.sub(r'&amp;', '&', clean_url)
        clean_url = re.sub(r'&#x[0-9A-Fa-f]+;', '', clean_url)
        
        # Skip if empty after cleaning
        if not clean_url or clean_url.isspace():
            continue
            
        # Skip internal Office URLs
        if is_internal_office_url(clean_url):
            continue
            
        # Validate it's a real URL format
        if re.match(r'^(https?://|www\.)[a-zA-Z0-9]', clean_url):
            # Ensure it has a proper domain structure
            if re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', clean_url):
                cleaned_urls.append(clean_url)
    
    return list(set(cleaned_urls))  # Remove duplicates

def extract_office_links_and_text(file_path, file_extension):
    """Extract links and text from Office documents with improved filtering"""
    links = []
    text_content = ""
    
    try:
        # Office files are actually ZIP archives
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # Extract text content from different Office file types
            if file_extension in ['docx', 'doc']:
                # Extract from Word document
                extracted_links = set()
                
                # Look in document.xml for content and links
                if 'word/document.xml' in zip_ref.namelist():
                    with zip_ref.open('word/document.xml') as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        text_content += re.sub(r'<[^>]+>', ' ', content)  # Basic tag removal
                        
                        # Extract hyperlinks from relationships
                        if 'word/_rels/document.xml.rels' in zip_ref.namelist():
                            with zip_ref.open('word/_rels/document.xml.rels') as rels_file:
                                rels_content = rels_file.read().decode('utf-8', errors='ignore')
                                # Extract Target attributes which contain URLs
                                url_matches = re.findall(r'Target="([^"]*)"', rels_content)
                                extracted_links.update(url_matches)
                
                # Also check for hyperlinks in the main document
                url_pattern = r'https?://[^\s<"]+|www\.[^\s<"]+'
                urls_from_text = re.findall(url_pattern, text_content)
                extracted_links.update(urls_from_text)
                
                links = list(extracted_links)
                    
            elif file_extension in ['xlsx', 'xls']:
                # Extract from Excel spreadsheet
                extracted_links = set()
                
                # Check shared strings and sheet files
                for name in zip_ref.namelist():
                    if name.startswith('xl/sharedStrings.xml') or name.startswith('xl/worksheets/sheet'):
                        try:
                            with zip_ref.open(name) as f:
                                content = f.read().decode('utf-8', errors='ignore')
                                clean_text = re.sub(r'<[^>]+>', ' ', content)
                                text_content += clean_text
                                
                                # Extract URLs from content
                                url_pattern = r'https?://[^\s<"]+|www\.[^\s<"]+'
                                urls = re.findall(url_pattern, clean_text)
                                extracted_links.update(urls)
                        except:
                            continue
                
                # Check Excel relationships for hyperlinks
                for name in zip_ref.namelist():
                    if name.startswith('xl/worksheets/_rels/sheet') and name.endswith('.rels'):
                        try:
                            with zip_ref.open(name) as rels_file:
                                rels_content = rels_file.read().decode('utf-8', errors='ignore')
                                url_matches = re.findall(r'Target="([^"]*)"', rels_content)
                                extracted_links.update(url_matches)
                        except:
                            continue
                
                links = list(extracted_links)
                    
            elif file_extension in ['pptx', 'ppt']:
                # Extract from PowerPoint presentation
                extracted_links = set()
                
                for name in zip_ref.namelist():
                    if name.startswith('ppt/slides/slide') and name.endswith('.xml'):
                        try:
                            with zip_ref.open(name) as f:
                                content = f.read().decode('utf-8', errors='ignore')
                                clean_text = re.sub(r'<[^>]+>', ' ', content)
                                text_content += clean_text
                                
                                # Extract URLs from content
                                url_pattern = r'https?://[^\s<"]+|www\.[^\s<"]+'
                                urls = re.findall(url_pattern, clean_text)
                                extracted_links.update(urls)
                        except:
                            continue
                
                # Check PowerPoint relationships
                for name in zip_ref.namelist():
                    if name.startswith('ppt/slides/_rels/slide') and name.endswith('.rels'):
                        try:
                            with zip_ref.open(name) as rels_file:
                                rels_content = rels_file.read().decode('utf-8', errors='ignore')
                                url_matches = re.findall(r'Target="([^"]*)"', rels_content)
                                extracted_links.update(url_matches)
                        except:
                            continue
                
                links = list(extracted_links)
                    
    except zipfile.BadZipFile:
        # Handle older .doc, .xls, .ppt files (OLE format)
        try:
            if olefile.isOleFile(file_path):
                ole = olefile.OleFileIO(file_path)
                text_content = "OLE Document - Limited analysis available"
                
                # Check for macros in older Office files (potential threat indicator)
                if file_extension in ['doc', 'xls', 'ppt']:
                    if ole.exists('Macros'):
                        text_content += "\n[WARNING] Macros detected in document"
        except:
            pass
    except Exception as e:
        print(f"Error reading Office document: {e}")
    
    # Clean and filter the extracted links
    cleaned_links = clean_and_filter_urls(links)
    
    return cleaned_links, text_content

def extract_ole_metadata(file_path):
    """Extract metadata from older Office formats (DOC, XLS, PPT)"""
    metadata = {}
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            
            # Common OLE properties that might contain useful info
            properties = {
                'Title': 'Title',
                'Subject': 'Subject', 
                'Author': 'Author',
                'Keywords': 'Keywords',
                'Comments': 'Comments',
                'LastSavedBy': 'Last Saved By',
                'RevisionNumber': 'Revision Number',
                'TotalEditingTime': 'Total Editing Time'
            }
            
            for prop, name in properties.items():
                try:
                    # Try to read property streams
                    if ole.exists(f'\\x05SummaryInformation'):
                        # This is a simplified approach - real implementation would parse the property stream
                        metadata[name] = "Available"
                except:
                    pass
                    
            # Check for macros (high risk indicator)
            if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'):
                metadata['Macros'] = 'Yes'
                
    except Exception as e:
        print(f"Error extracting OLE metadata: {e}")
    
    return metadata

def analyze_urls(urls):
    """Analyze extracted URLs for threats with improved detection and scoring"""
    threats = []
    safe_urls = []
    
    # Expanded list of suspicious patterns with severity levels
    high_risk_patterns = [
        'phishing', 'malware', 'trojan', 'ransomware', 'virus', 'exploit',
        'keylogger', 'botnet', 'rootkit', 'backdoor', 'spyware', 'fake-bank',
        'bank-security', 'password-reset', 'account-verify', 'credit-card',
        'social-security', 'ssn', 'irs-', 'tax-refund', 'paypal-verify',
        'bitcoin-generator', 'crypto-miner', 'hack-tool', 'keygen', 'crack',
        'account-suspended', 'security-breach', 'unauthorized', 'compromised',
        'login-alert', 'verify-identity', 'secure-account', 'suspicious-activity'
    ]
    
    medium_risk_patterns = [
        'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
        'adf.ly', 'shorte.st', 'bc.vc', 'adfly', 'urlz.fr', 'u.to', 'j.mp',
        'buzurl', 'cutt.us', 'u.bb', 'yourls.org', 'free-', 'gift-', 'prize-',
        'winner-', 'lottery-', 'reward-', 'bonus-', 'offer-', 'discount-',
        'claim-', 'limited-time', 'special-offer', 'exclusive-deal'
    ]
    
    # Microsoft and other trusted domains (reduce false positives)
    trusted_domains = [
        'microsoft.com', 'office.com', 'windows.com', 'adobe.com', 'google.com',
        'apple.com', 'mozilla.org', 'w3.org', 'openxmlformats.org', 'purl.org'
    ]
    
    for url in urls:
        url_lower = url.lower()
        threat_level = 'safe'
        reasons = []
        severity_score = 0
        
        # Skip trusted domains (reduce false positives)
        if any(domain in url_lower for domain in trusted_domains):
            safe_urls.append(url)
            continue
        
        # Check for high risk patterns
        for pattern in high_risk_patterns:
            if pattern in url_lower:
                threat_level = 'malicious'
                reasons.append(f'High-risk pattern: {pattern}')
                severity_score += 3
                break
        
        # Check for medium risk patterns (only if not already high risk)
        if threat_level == 'safe':
            for pattern in medium_risk_patterns:
                if pattern in url_lower:
                    threat_level = 'suspicious'
                    reasons.append(f'Medium-risk pattern: {pattern}')
                    severity_score += 1
                    break
        
        # Additional checks
        if threat_level == 'safe':
            # Check for HTTP
            if url_lower.startswith('http://') and not url_lower.startswith('https://'):
                threat_level = 'suspicious'
                reasons.append('Uses HTTP instead of HTTPS')
                severity_score += 1
                
            # Check for IP addresses in URL
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.search(ip_pattern, url):
                threat_level = 'suspicious'
                reasons.append('Contains IP address')
                severity_score += 1
                
            # Check for very long URLs
            if len(url) > 100:
                threat_level = 'suspicious'
                reasons.append('Unusually long URL')
                severity_score += 1
                
            # Check for multiple subdomains
            if url_lower.count('.') > 4:
                threat_level = 'suspicious'
                reasons.append('Multiple subdomains')
                severity_score += 1
        
        if threat_level == 'safe':
            safe_urls.append(url)
        else:
            threats.append({
                'url': url,
                'threat_level': threat_level,
                'reasons': reasons,
                'severity_score': severity_score
            })
    
    return threats, safe_urls

def analyze_text_content(text):
    """Analyze text content for suspicious patterns with scoring"""
    suspicious_content = []
    
    # Only analyze if there's meaningful text content
    if not text or len(text.strip()) < 10:
        return suspicious_content
    
    # Suspicious keywords with severity levels
    high_severity_keywords = {
        'password': 3, 'login': 3, 'credential': 3, 'verify': 2, 'confirm': 2,
        'account': 2, 'suspended': 3, 'locked': 3, 'compromised': 3, 'breach': 3,
        'hack': 3, 'unauthorized': 3, 'bitcoin': 3, 'crypto': 3, 'payment': 2,
        'social security': 3, 'ssn': 3, 'credit card': 3, 'debit card': 3,
        'bank account': 3, 'irs': 3, 'tax': 2, 'refund': 2, 'security alert': 3,
        'urgent action': 3, 'immediately': 2, 'emergency': 2, 'critical': 2
    }
    
    medium_severity_keywords = {
        'urgent': 2, 'immediate': 2, 'action required': 2, 'security': 1,
        'alert': 2, 'update': 1, 'prize': 1, 'winner': 1, 'lottery': 1,
        'reward': 1, 'free': 1, 'gift': 1, 'bonus': 1, 'offer': 1,
        'click here': 1, 'download now': 2, 'install': 1, 'limited time': 1,
        'special offer': 1, 'exclusive': 1, 'claim': 1, 'congratulations': 1
    }
    
    text_lower = text.lower()
    
    # Check high severity keywords
    for keyword, severity in high_severity_keywords.items():
        if keyword in text_lower:
            count = text_lower.count(keyword)
            suspicious_content.append({
                'type': 'high_risk_keyword',
                'content': keyword,
                'count': count,
                'severity': 'high',
                'score': severity * count
            })
    
    # Check medium severity keywords
    for keyword, severity in medium_severity_keywords.items():
        if keyword in text_lower:
            count = text_lower.count(keyword)
            # Only add if not already in high severity
            if not any(item['content'] == keyword for item in suspicious_content):
                suspicious_content.append({
                    'type': 'medium_risk_keyword',
                    'content': keyword,
                    'count': count,
                    'severity': 'medium',
                    'score': severity * count
                })
    
    return suspicious_content

def check_virustotal(file_hash):
    """Check file hash against VirusTotal"""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'YOUR_VIRUSTOTAL_API_KEY':
        # For testing, simulate some detections for known malicious hashes
        test_malicious_hashes = [
            'd41d8cd98f00b204e9800998ecf8427e',  # Empty file hash
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # Empty SHA256
        ]
        
        if file_hash in test_malicious_hashes:
            return {
                'positives': 45,
                'total': 65,
                'detected': True,
                'message': 'Simulated malicious file detection'
            }
        return {'positives': 0, 'total': 0, 'detected': False, 'message': 'VirusTotal API key not configured'}
    
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 1:
                return result
            else:
                return {'positives': 0, 'total': 0, 'detected': False, 'message': 'File not found in VirusTotal database'}
        else:
            return {'positives': 0, 'total': 0, 'detected': False, 'message': 'VirusTotal API error'}
    except Exception as e:
        return {'positives': 0, 'total': 0, 'detected': False, 'message': f'VirusTotal check failed: {str(e)}'}

def calculate_threat_score(analysis_results):
    """Calculate overall threat score with better differentiation"""
    score = 0
    max_score = 100
    
    # Base weights
    weights = {
        'malicious_hash': 60,
        'suspicious_urls': 35,
        'suspicious_content': 25,
        'url_count_penalty': 15,
        'content_density': 10,
        'file_type_risk': 20,  # New: risk based on file type
        'macro_detection': 40  # New: high risk for macros
    }
    
    # 1. VirusTotal hash analysis
    vt_results = analysis_results.get('virustotal_results', {})
    if vt_results.get('positives', 0) > 0:
        positives = vt_results['positives']
        total = max(vt_results.get('total', 1), 1)
        detection_ratio = positives / total
        
        if detection_ratio > 0.5:
            score += weights['malicious_hash']
        elif detection_ratio > 0.2:
            score += weights['malicious_hash'] * 0.6
        else:
            score += weights['malicious_hash'] * 0.3
    
    # 2. URL-based threats
    suspicious_urls = analysis_results.get('suspicious_urls', [])
    if suspicious_urls:
        total_url_severity = sum(url.get('severity_score', 1) for url in suspicious_urls)
        
        malicious_urls = [url for url in suspicious_urls if url.get('threat_level') == 'malicious']
        suspicious_url_count = len(suspicious_urls) - len(malicious_urls)
        
        if suspicious_url_count > 0:
            url_base_score = min(suspicious_url_count * 3, weights['suspicious_urls'] * 0.4)
            score += url_base_score
            
            if malicious_url_count > 0:
                malicious_bonus = min(malicious_url_count * 8, weights['suspicious_urls'] * 0.6)
                score += malicious_bonus
            
            severity_bonus = min(total_url_severity * 2, weights['suspicious_urls'] * 0.3)
            score += severity_bonus
    
    # 3. Suspicious content analysis
    suspicious_content = analysis_results.get('suspicious_content', [])
    if suspicious_content:
        total_content_score = sum(item.get('score', 1) for item in suspicious_content)
        
        high_risk_content = [item for item in suspicious_content if item.get('severity') == 'high']
        medium_risk_content = [item for item in suspicious_content if item.get('severity') == 'medium']
        
        content_base_score = min(len(suspicious_content) * 2, weights['suspicious_content'] * 0.5)
        score += content_base_score
        
        if high_risk_content:
            high_risk_bonus = min(len(high_risk_content) * 5, weights['suspicious_content'] * 0.5)
            score += high_risk_bonus
    
    # 4. File type risk assessment
    file_type = analysis_results.get('file_type', '').lower()
    file_extension = analysis_results.get('file_extension', '').lower()
    
    # Higher risk for executable-like formats and macros
    if file_extension in ['doc', 'xls', 'ppt']:  # Older formats that support macros
        score += weights['file_type_risk'] * 0.8
    elif file_extension in ['docm', 'xlsm', 'pptm']:  # Newer macro-enabled formats
        score += weights['file_type_risk']
    elif file_extension in ['exe', 'scr', 'bat', 'cmd', 'com', 'pif']:
        score += weights['file_type_risk']
    
    # 5. Macro detection (high risk)
    metadata = analysis_results.get('metadata', {})
    if metadata.get('Macros') == 'Yes':
        score += weights['macro_detection']
    
    # 6. URL count penalty
    all_urls = analysis_results.get('extracted_links', [])
    if len(all_urls) > 10:
        penalty = min((len(all_urls) - 10) * 1, weights['url_count_penalty'])
        score += penalty
    
    # 7. Content density penalty
    text_content = analysis_results.get('text_content', '')
    if text_content:
        word_count = len(text_content.split())
        suspicious_word_count = sum(item.get('count', 1) for item in suspicious_content)
        if word_count > 0:
            density = suspicious_word_count / word_count
            if density > 0.1:
                density_penalty = min(density * 50, weights['content_density'])
                score += density_penalty
    
    # Ensure score is within bounds and rounded
    final_score = min(round(score), max_score)
    
    # Debug logging
    print(f"DEBUG - Threat Score Breakdown:")
    print(f"  Final Score: {final_score}")
    print(f"  File Type: {file_type}")
    print(f"  Suspicious URLs: {len(suspicious_urls)}")
    print(f"  Malicious URLs: {len([u for u in suspicious_urls if u.get('threat_level') == 'malicious'])}")
    print(f"  Suspicious Content: {len(suspicious_content)}")
    print(f"  High Risk Content: {len([c for c in suspicious_content if c.get('severity') == 'high'])}")
    print(f"  VirusTotal Positives: {vt_results.get('positives', 0)}")
    print(f"  Macros Detected: {metadata.get('Macros', 'No')}")
    print(f"  Total URLs: {len(all_urls)}")
    
    return final_score

@app.route('/')
def index():
    return render_template('index.html')

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
        'file_extension': file_extension,
        'file_size': os.path.getsize(file_path),
        'threat_score': 0,
        'risk_level': 'low',
        'analysis_details': [],
        'suspicious_urls': [],
        'safe_urls': [],
        'extracted_links': [],
        'virustotal_results': {},
        'suspicious_content': [],
        'text_content': '',
        'metadata': {},
        'analysis_timestamp': datetime.now().isoformat()
    }
    
    # Calculate file hash
    file_hash = calculate_file_hash(file_path)
    analysis_results['file_hash'] = file_hash
    
    # Check VirusTotal
    vt_results = check_virustotal(file_hash)
    analysis_results['virustotal_results'] = vt_results
    
    # Extract content based on file type
    if file_extension == 'pdf':
        links, text_content = extract_pdf_links_and_text(file_path)
        analysis_results['extracted_links'] = links
        analysis_results['text_content'] = text_content[:2000]  # First 2000 chars
        
    elif file_extension in ['docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt']:
        links, text_content = extract_office_links_and_text(file_path, file_extension)
        analysis_results['extracted_links'] = links
        analysis_results['text_content'] = text_content[:2000]
        
        # Extract additional metadata for older Office formats
        if file_extension in ['doc', 'xls', 'ppt']:
            metadata = extract_ole_metadata(file_path)
            analysis_results['metadata'] = metadata
    
    # Analyze URLs (for all file types)
    suspicious_urls, safe_urls = analyze_urls(analysis_results['extracted_links'])
    analysis_results['suspicious_urls'] = suspicious_urls
    analysis_results['safe_urls'] = safe_urls
    
    # Analyze text content (for all file types)
    suspicious_content = analyze_text_content(analysis_results['text_content'])
    analysis_results['suspicious_content'] = suspicious_content
    
    # Calculate threat score
    threat_score = calculate_threat_score(analysis_results)
    analysis_results['threat_score'] = threat_score
    
    # Determine risk level with better granularity
    if threat_score >= 80:
        analysis_results['risk_level'] = 'very-high'
    elif threat_score >= 60:
        analysis_results['risk_level'] = 'high'
    elif threat_score >= 40:
        analysis_results['risk_level'] = 'medium'
    elif threat_score >= 20:
        analysis_results['risk_level'] = 'low'
    else:
        analysis_results['risk_level'] = 'very-low'
    
    # Generate detailed analysis
    analysis_results['analysis_details'] = generate_analysis_details(analysis_results)
    
    return analysis_results

def generate_analysis_details(results):
    """Generate human-readable analysis details with scoring info"""
    details = []
    
    # Hash analysis
    vt_results = results['virustotal_results']
    if vt_results.get('positives', 0) > 0:
        positives = vt_results['positives']
        total = vt_results.get('total', 1)
        details.append(f"🚨 MALICIOUS HASH: Detected by {positives}/{total} antivirus engines (+60 points)")
    else:
        details.append("✅ No antivirus detections found")
    
    # URL analysis
    suspicious_urls = results.get('suspicious_urls', [])
    safe_urls = results.get('safe_urls', [])
    
    malicious_urls = [url for url in suspicious_urls if url.get('threat_level') == 'malicious']
    suspicious_url_count = len(suspicious_urls) - len(malicious_urls)
    
    if malicious_urls:
        details.append(f"🔴 MALICIOUS URLs: {len(malicious_urls)} found (+8 points each)")
    if suspicious_url_count > 0:
        details.append(f"🟡 SUSPICIOUS URLs: {suspicious_url_count} found (+3 points each)")
    if not suspicious_urls:
        details.append("✅ No suspicious URLs detected")
        
    if safe_urls:
        details.append(f"🔗 Normal URLs: {len(safe_urls)} found")
    
    # Content analysis
    suspicious_content = results.get('suspicious_content', [])
    high_risk_content = [c for c in suspicious_content if c.get('severity') == 'high']
    medium_risk_content = [c for c in suspicious_content if c.get('severity') == 'medium']
    
    if high_risk_content:
        details.append(f"📝 HIGH-RISK CONTENT: {len(high_risk_content)} patterns found (+5 points each)")
    if medium_risk_content:
        details.append(f"📝 MEDIUM-RISK CONTENT: {len(medium_risk_content)} patterns found (+2 points each)")
    
    # File type risk
    file_extension = results.get('file_extension', '')
    if file_extension in ['doc', 'xls', 'ppt']:
        details.append(f"⚠️ OLDER OFFICE FORMAT: {file_extension.upper()} files can contain macros (+16 points)")
    elif file_extension in ['docm', 'xlsm', 'pptm']:
        details.append(f"⚠️ MACRO-ENABLED FILE: {file_extension.upper()} format supports macros (+20 points)")
    
    # Macro detection
    metadata = results.get('metadata', {})
    if metadata.get('Macros') == 'Yes':
        details.append(f"🚨 MACROS DETECTED: Document contains macros (+40 points)")
    
    # File info
    details.append(f"📄 File type: {results['file_type']}")
    details.append(f"📊 File size: {format_file_size(results['file_size'])}")
    
    # Total URLs penalty
    all_urls = results.get('extracted_links', [])
    if len(all_urls) > 10:
        details.append(f"🔗 URL COUNT: {len(all_urls)} URLs found (+{min((len(all_urls)-10), 15)} points)")
    
    # Threat score explanation
    threat_score = results['threat_score']
    if threat_score >= 80:
        details.append("🎯 VERY HIGH RISK: Multiple high-severity threats detected")
    elif threat_score >= 60:
        details.append("🎯 HIGH RISK: Significant threat indicators present")
    elif threat_score >= 40:
        details.append("🎯 MEDIUM RISK: Some suspicious elements found")
    elif threat_score >= 20:
        details.append("🎯 LOW RISK: Minimal threat indicators")
    else:
        details.append("🎯 VERY LOW RISK: No significant threats detected")
    
    return details

def format_file_size(bytes):
    """Format file size in human readable format"""
    if bytes == 0:
        return "0 Bytes"
    k = 1024
    sizes = ["Bytes", "KB", "MB", "GB"]
    i = int(math.floor(math.log(bytes) / math.log(k)))
    return f"{round(bytes / (k ** i), 2)} {sizes[i]}"

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Threat-IQ API is running',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')