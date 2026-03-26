"""
Quishing Prevention Web Application
A Flask-based web application to detect and prevent QR code phishing attacks.
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
import re
import ssl
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse
import hashlib
import os
import tempfile
import io
from PIL import Image
from pyzbar.pyzbar import decode as decode_qr
import fitz  # PyMuPDF for PDF processing
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
CORS(app)

# Simple in-memory cache for URL analysis results
url_analysis_cache = {}
MAX_CACHE_SIZE = 500

# API Keys
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '1591a994449ea1a1d1de37b5a196192014fe7cfa4eefb2d0ed413f58cbc5e9f7')
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', 'AIzaSyCntAif5lTWFiW8Le7JS3_qvjMPUyhHook')

# Known legitimate domains for typosquatting detection
LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
    'paypal.com', 'netflix.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'youtube.com', 'whatsapp.com', 'telegram.org', 'github.com', 'dropbox.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com'
]

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'password', 'credential', 'suspend', 'locked', 'unusual',
    'authenticate', 'wallet', 'prize', 'winner', 'urgent', 'immediate'
]

# Known legitimate UPI apps/handles
LEGITIMATE_UPI_HANDLES = [
    '@paytm', '@ybl', '@upi', '@okaxis', '@okhdfcbank', '@oksbi',
    '@okicici', '@apl', '@axisbank', '@ibl', '@sbi', '@hdfcbank'
]

# Suspicious patterns in UPI IDs
SUSPICIOUS_UPI_PATTERNS = [
    'prize', 'winner', 'lottery', 'claim', 'reward', 'lucky',
    'refund', 'cashback', 'offer', 'free', 'gift'
]


def detect_qr_type(content):
    """Detect the type of QR code content."""
    content_lower = content.lower().strip()
    
    # Check for UPI payment
    if content_lower.startswith('upi://') or content_lower.startswith('upi:'):
        return 'upi'
    
    # Check for Bitcoin
    if content_lower.startswith('bitcoin:') or (len(content) in [26, 35, 42, 62] and content.startswith(('1', '3', 'bc1'))):
        return 'bitcoin'
    
    # Check for Ethereum
    if content_lower.startswith('ethereum:') or (content.startswith('0x') and len(content) == 42):
        return 'ethereum'
    
    # Check for standard URLs
    if content_lower.startswith(('http://', 'https://', 'www.')):
        return 'url'
    
    # Check if it looks like a domain
    if '.' in content and not ' ' in content and len(content) < 100:
        return 'url'
    
    # Check for other payment schemes
    if ':' in content:
        scheme = content_lower.split(':')[0]
        if scheme in ['paypal', 'venmo', 'cashapp', 'gpay', 'phonepe']:
            return 'payment'
    
    return 'unknown'


def parse_upi_qr(upi_string):
    """Parse a UPI QR code string and extract details."""
    try:
        # Remove 'upi://' or 'upi:' prefix
        if upi_string.lower().startswith('upi://'):
            params_string = upi_string[6:]
        elif upi_string.lower().startswith('upi:'):
            params_string = upi_string[4:]
        else:
            params_string = upi_string
        
        # Parse query parameters
        if '?' in params_string:
            path, query = params_string.split('?', 1)
        else:
            query = params_string
            path = ''
        
        # Parse parameters
        params = {}
        if '&' in query or '=' in query:
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key.lower()] = requests.utils.unquote(value)
        
        return {
            'success': True,
            'payee_address': params.get('pa', params.get('payeeaddress', 'Unknown')),
            'payee_name': params.get('pn', params.get('payeename', 'Unknown')),
            'amount': params.get('am', params.get('amount', 'Not specified')),
            'currency': params.get('cu', 'INR'),
            'transaction_note': params.get('tn', params.get('transactionnote', '')),
            'merchant_code': params.get('mc', params.get('merchantcode', '')),
            'transaction_id': params.get('tid', params.get('transactionid', '')),
            'raw_params': params
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def validate_upi_id(upi_id):
    """Validate a UPI ID and check for suspicious patterns."""
    issues = []
    warnings = []
    
    if not upi_id or upi_id == 'Unknown':
        return {
            'status': 'warning',
            'message': 'UPI ID not found in QR code',
            'valid_format': False,
            'issues': ['Missing UPI ID']
        }
    
    upi_lower = upi_id.lower()
    
    # Check format: should be something@handle
    if '@' not in upi_id:
        issues.append('Invalid UPI ID format (missing @)')
    else:
        parts = upi_id.split('@')
        if len(parts) != 2:
            issues.append('Invalid UPI ID format')
        else:
            username, handle = parts
            
            # Check if handle is from a known legitimate provider
            handle_with_at = '@' + handle.lower()
            is_known_handle = any(handle_with_at == legit for legit in LEGITIMATE_UPI_HANDLES)
            
            if not is_known_handle:
                warnings.append(f'Unknown UPI handle: @{handle}')
            
            # Check for suspicious patterns in username
            for pattern in SUSPICIOUS_UPI_PATTERNS:
                if pattern in username.lower():
                    issues.append(f'Suspicious keyword in UPI ID: {pattern}')
            
            # Check for random-looking usernames (potential scam)
            if len(username) > 20:
                warnings.append('Unusually long UPI username')
            
            # Check for excessive numbers (often used in scam IDs)
            digit_count = sum(c.isdigit() for c in username)
            if digit_count > len(username) * 0.7 and len(username) > 5:
                warnings.append('UPI ID contains mostly numbers (common in scams)')
    
    if issues:
        return {
            'status': 'danger',
            'message': 'Suspicious UPI ID detected',
            'valid_format': '@' in upi_id,
            'issues': issues,
            'warnings': warnings
        }
    elif warnings:
        return {
            'status': 'warning',
            'message': 'UPI ID has some concerns',
            'valid_format': True,
            'issues': [],
            'warnings': warnings
        }
    else:
        return {
            'status': 'safe',
            'message': 'UPI ID format looks valid',
            'valid_format': True,
            'issues': [],
            'warnings': []
        }


def check_crypto_address(address, crypto_type):
    """Validate and check cryptocurrency addresses."""
    issues = []
    warnings = []
    
    if crypto_type == 'bitcoin':
        # Remove bitcoin: prefix if present
        if address.lower().startswith('bitcoin:'):
            address = address[8:].split('?')[0]  # Remove prefix and any parameters
        
        # Basic Bitcoin address validation
        if address.startswith('1'):
            if len(address) not in range(26, 36):
                issues.append('Invalid Bitcoin P2PKH address length')
            else:
                warnings.append('Legacy Bitcoin address (P2PKH)')
        elif address.startswith('3'):
            if len(address) not in range(26, 36):
                issues.append('Invalid Bitcoin P2SH address length')
        elif address.startswith('bc1'):
            if len(address) not in range(42, 63):
                issues.append('Invalid Bitcoin Bech32 address length')
        else:
            issues.append('Unrecognized Bitcoin address format')
        
        # Check for known scam address patterns (example - in production, use a database)
        warnings.append('Always verify crypto addresses through official channels')
        
    elif crypto_type == 'ethereum':
        # Remove ethereum: prefix if present
        if address.lower().startswith('ethereum:'):
            address = address[9:].split('?')[0]
        
        # Basic Ethereum address validation
        if not address.startswith('0x'):
            issues.append('Ethereum address should start with 0x')
        elif len(address) != 42:
            issues.append(f'Invalid Ethereum address length (expected 42, got {len(address)})')
        elif not all(c in '0123456789abcdefABCDEF' for c in address[2:]):
            issues.append('Ethereum address contains invalid characters')
        
        warnings.append('Always verify crypto addresses through official channels')
    
    if issues:
        return {
            'status': 'danger',
            'message': 'Invalid cryptocurrency address',
            'address': address,
            'crypto_type': crypto_type,
            'issues': issues
        }
    else:
        return {
            'status': 'warning',
            'message': 'Cryptocurrency payment detected - verify carefully',
            'address': address,
            'crypto_type': crypto_type,
            'warnings': warnings
        }


def analyze_payment_qr(qr_content, qr_type):
    """Analyze a payment QR code (UPI, crypto, etc.)."""
    result = {
        'qr_type': qr_type,
        'raw_content': qr_content,
        'checks': {}
    }
    
    if qr_type == 'upi':
        # Parse UPI details
        upi_data = parse_upi_qr(qr_content)
        result['payment_details'] = upi_data
        
        if upi_data['success']:
            # Validate UPI ID
            result['checks']['upi_validation'] = validate_upi_id(upi_data['payee_address'])
            
            # Check amount if specified
            amount = upi_data.get('amount', 'Not specified')
            if amount != 'Not specified':
                try:
                    amt_float = float(amount)
                    if amt_float > 100000:
                        result['checks']['amount_check'] = {
                            'status': 'warning',
                            'message': f'Large amount specified: ₹{amt_float:,.2f}'
                        }
                    else:
                        result['checks']['amount_check'] = {
                            'status': 'safe',
                            'message': f'Amount: ₹{amt_float:,.2f}'
                        }
                except:
                    result['checks']['amount_check'] = {
                        'status': 'warning',
                        'message': 'Could not parse amount'
                    }
            
            # Calculate risk score for UPI
            risk_score = 0
            if result['checks'].get('upi_validation', {}).get('status') == 'danger':
                risk_score += 50
            elif result['checks'].get('upi_validation', {}).get('status') == 'warning':
                risk_score += 25
            if result['checks'].get('amount_check', {}).get('status') == 'warning':
                risk_score += 15
            
            result['risk_score'] = min(100, risk_score)
            result['risk_level'] = get_risk_level(result['risk_score'])
            result['recommendation'] = get_payment_recommendation(result['risk_level'], 'upi')
        else:
            result['checks']['parse_error'] = {
                'status': 'danger',
                'message': f'Failed to parse UPI QR: {upi_data.get("error", "Unknown error")}'
            }
            result['risk_score'] = 70
            result['risk_level'] = 'high'
            result['recommendation'] = 'Could not parse this UPI QR code. Do not proceed with payment.'
    
    elif qr_type in ['bitcoin', 'ethereum']:
        result['checks']['crypto_check'] = check_crypto_address(qr_content, qr_type)
        
        # Parse amount if present in URL format
        if '?' in qr_content:
            params = qr_content.split('?')[1]
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    if key.lower() == 'amount':
                        result['requested_amount'] = value
        
        result['risk_score'] = 50  # Crypto payments always warrant caution
        result['risk_level'] = 'medium'
        result['recommendation'] = get_payment_recommendation('medium', qr_type)
    
    else:
        result['checks']['unknown_payment'] = {
            'status': 'warning',
            'message': f'Unknown payment type: {qr_type}'
        }
        result['risk_score'] = 60
        result['risk_level'] = 'medium'
        result['recommendation'] = 'Unknown payment format. Verify through official channels before proceeding.'
    
    return result


def get_payment_recommendation(risk_level, payment_type):
    """Get recommendation for payment QR codes."""
    if payment_type == 'upi':
        recommendations = {
            'high': 'DANGER: This UPI QR code shows signs of fraud. Do NOT make this payment!',
            'medium': 'CAUTION: Verify the payee details carefully before making this payment.',
            'low': 'UPI details appear normal, but always verify the payee before paying.'
        }
    elif payment_type in ['bitcoin', 'ethereum']:
        recommendations = {
            'high': 'DANGER: This cryptocurrency address appears invalid or suspicious!',
            'medium': 'CAUTION: Cryptocurrency transactions are irreversible. Triple-check the address!',
            'low': 'Address format is valid, but always verify through official sources.'
        }
    else:
        recommendations = {
            'high': 'DANGER: This payment request shows multiple red flags. Do NOT proceed!',
            'medium': 'CAUTION: Verify this payment request through official channels.',
            'low': 'Exercise normal caution with this payment request.'
        }
    return recommendations.get(risk_level, 'Unable to determine safety.')


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/api/extract-pdf', methods=['POST'])
def extract_qr_from_pdf():
    """Extract QR codes from uploaded PDF file."""
    if 'pdf' not in request.files:
        return jsonify({'error': 'No PDF file provided'}), 400
    
    pdf_file = request.files['pdf']
    
    if pdf_file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not pdf_file.filename.lower().endswith('.pdf'):
        return jsonify({'error': 'File must be a PDF'}), 400
    
    try:
        # Read PDF file
        pdf_bytes = pdf_file.read()
        
        # Extract QR codes from PDF
        extracted_urls = extract_qr_codes_from_pdf(pdf_bytes)
        
        if not extracted_urls:
            return jsonify({
                'success': True,
                'message': 'No QR codes found in the PDF',
                'qr_codes': [],
                'total_found': 0
            })
        
        # Analyze each extracted QR code
        analyzed_results = []
        for i, url_info in enumerate(extracted_urls):
            qr_content = url_info['url']
            qr_type = detect_qr_type(qr_content)
            
            try:
                # Handle payment QR codes differently
                if qr_type in ['upi', 'bitcoin', 'ethereum', 'payment']:
                    payment_result = analyze_payment_qr(qr_content, qr_type)
                    analyzed_results.append({
                        'index': i + 1,
                        'qr_content': qr_content,
                        'qr_type': qr_type,
                        'page': url_info['page'],
                        'is_payment': True,
                        **payment_result
                    })
                    continue
                
                # Handle unknown QR types
                if qr_type == 'unknown':
                    analyzed_results.append({
                        'index': i + 1,
                        'qr_content': qr_content,
                        'qr_type': 'unknown',
                        'page': url_info['page'],
                        'risk_score': 30,
                        'risk_level': 'medium',
                        'recommendation': 'Unknown QR code format. Could not analyze.',
                        'checks': {
                            'format_check': {
                                'status': 'warning',
                                'message': 'Unrecognized QR code format'
                            }
                        }
                    })
                    continue
                
                # Handle URL QR codes (existing logic)
                url = qr_content
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                # Perform security checks
                checks = {}
                checks['url_analysis'] = analyze_url_structure(url, domain)
                checks['ssl_check'] = check_ssl_certificate(domain)
                checks['domain_age'] = check_domain_age(domain)
                checks['typosquatting'] = detect_typosquatting(domain)
                checks['suspicious_keywords'] = check_suspicious_keywords(url)
                
                # API checks
                if VIRUSTOTAL_API_KEY:
                    checks['virustotal'] = check_virustotal(url)
                else:
                    checks['virustotal'] = {'status': 'skipped', 'message': 'API key not configured'}
                
                if GOOGLE_SAFE_BROWSING_API_KEY:
                    checks['google_safe_browsing'] = check_google_safe_browsing(url)
                else:
                    checks['google_safe_browsing'] = {'status': 'skipped', 'message': 'API key not configured'}
                
                risk_score = calculate_risk_score(checks)
                risk_level = get_risk_level(risk_score)
                
                analyzed_results.append({
                    'index': i + 1,
                    'url': url,
                    'qr_type': 'url',
                    'domain': domain,
                    'page': url_info['page'],
                    'is_payment': False,
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'recommendation': get_recommendation(risk_level),
                    'checks': checks
                })
            except Exception as e:
                analyzed_results.append({
                    'index': i + 1,
                    'qr_content': qr_content,
                    'page': url_info['page'],
                    'error': str(e),
                    'risk_level': 'unknown'
                })
        
        return jsonify({
            'success': True,
            'message': f'Found {len(extracted_urls)} QR code(s) in the PDF',
            'qr_codes': analyzed_results,
            'total_found': len(extracted_urls)
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to process PDF: {str(e)}'}), 500


def extract_qr_codes_from_pdf(pdf_bytes):
    """Extract all QR codes from a PDF file."""
    extracted_urls = []
    
    try:
        # Open PDF with PyMuPDF
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        
        for page_num in range(len(pdf_document)):
            page = pdf_document.load_page(page_num)
            
            # Convert page to image with high resolution
            # Use a zoom factor for better QR code detection
            zoom = 2.0  # Increase resolution
            mat = fitz.Matrix(zoom, zoom)
            pix = page.get_pixmap(matrix=mat)
            
            # Convert to PIL Image
            img_data = pix.tobytes("png")
            image = Image.open(io.BytesIO(img_data))
            
            # Decode QR codes from image
            qr_codes = decode_qr(image)
            
            for qr in qr_codes:
                try:
                    url = qr.data.decode('utf-8')
                    # Only add if it looks like a URL or could be one
                    if url and len(url) > 0:
                        extracted_urls.append({
                            'url': url,
                            'page': page_num + 1,
                            'type': qr.type
                        })
                except:
                    continue
            
            # Also try to extract QR codes from embedded images in the PDF
            image_list = page.get_images()
            for img_index, img in enumerate(image_list):
                try:
                    xref = img[0]
                    base_image = pdf_document.extract_image(xref)
                    image_bytes = base_image["image"]
                    
                    # Convert to PIL Image
                    pil_image = Image.open(io.BytesIO(image_bytes))
                    
                    # Try to decode QR codes
                    qr_codes = decode_qr(pil_image)
                    
                    for qr in qr_codes:
                        try:
                            url = qr.data.decode('utf-8')
                            if url and len(url) > 0:
                                # Check for duplicates
                                if not any(u['url'] == url for u in extracted_urls):
                                    extracted_urls.append({
                                        'url': url,
                                        'page': page_num + 1,
                                        'type': qr.type
                                    })
                        except:
                            continue
                except:
                    continue
        
        pdf_document.close()
        
    except Exception as e:
        raise Exception(f"PDF processing error: {str(e)}")
    
    return extracted_urls


@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Analyze a URL or payment QR code for potential security threats."""
    data = request.get_json()
    content = data.get('url', '')
    
    if not content:
        return jsonify({'error': 'No content provided'}), 400
    
    # Check cache first for instant response
    cache_key = hashlib.sha256(content.encode()).hexdigest()
    if cache_key in url_analysis_cache:
        result = url_analysis_cache[cache_key].copy()
        result['timestamp'] = datetime.now().isoformat()
        result['cached'] = True
        return jsonify(result)
    
    # Detect QR type first
    qr_type = detect_qr_type(content)
    
    # Handle payment QR codes
    if qr_type in ['upi', 'bitcoin', 'ethereum', 'payment']:
        try:
            result = analyze_payment_qr(content, qr_type)
            result['timestamp'] = datetime.now().isoformat()
            result['is_payment'] = True
            result['cached'] = False
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # Handle unknown types
    if qr_type == 'unknown':
        return jsonify({
            'qr_type': 'unknown',
            'raw_content': content,
            'timestamp': datetime.now().isoformat(),
            'risk_score': 30,
            'risk_level': 'medium',
            'recommendation': 'Unknown content format. Could not analyze as URL or payment.',
            'checks': {
                'format_check': {
                    'status': 'warning',
                    'message': 'Unrecognized content format'
                }
            },
            'cached': False
        })
    
    # Handle URL type with parallel execution and optimization
    url = content
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        results = {
            'url': url,
            'qr_type': 'url',
            'is_payment': False,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        # Run fast checks first (no expensive network calls)
        results['checks']['url_analysis'] = analyze_url_structure(url, domain)
        results['checks']['suspicious_keywords'] = check_suspicious_keywords(url)
        results['checks']['typosquatting'] = detect_typosquatting(domain)
        
        # Early exit: if multiple danger signals detected, skip expensive checks
        danger_count = sum(1 for check_name in ['url_analysis', 'suspicious_keywords', 'typosquatting']
                          if results['checks'][check_name].get('status') == 'danger')
        
        if danger_count >= 2:
            # Obvious phishing detected - skip expensive network checks
            results['checks']['ssl_check'] = {'status': 'skipped', 'message': 'Skipped due to obvious phishing signals'}
            results['checks']['domain_age'] = {'status': 'skipped', 'message': 'Skipped due to obvious phishing signals'}
            results['checks']['virustotal'] = {'status': 'skipped', 'message': 'Skipped due to obvious phishing signals'}
            results['checks']['google_safe_browsing'] = {'status': 'skipped', 'message': 'Skipped due to obvious phishing signals'}
        else:
            # Run remaining checks in parallel
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(check_ssl_certificate, domain): 'ssl_check',
                    executor.submit(check_domain_age, domain): 'domain_age',
                }
                
                # Add API checks only if keys are configured
                if VIRUSTOTAL_API_KEY:
                    futures[executor.submit(check_virustotal, url)] = 'virustotal'
                else:
                    results['checks']['virustotal'] = {'status': 'skipped', 'message': 'API key not configured'}
                
                if GOOGLE_SAFE_BROWSING_API_KEY:
                    futures[executor.submit(check_google_safe_browsing, url)] = 'google_safe_browsing'
                else:
                    results['checks']['google_safe_browsing'] = {'status': 'skipped', 'message': 'API key not configured'}
                
                # Collect results as they complete
                for future in as_completed(futures):
                    check_name = futures[future]
                    try:
                        results['checks'][check_name] = future.result()
                    except Exception as e:
                        results['checks'][check_name] = {
                            'status': 'warning',
                            'message': f'{check_name} check failed: {str(e)}'
                        }
        
        # Calculate overall risk score
        results['risk_score'] = calculate_risk_score(results['checks'])
        results['risk_level'] = get_risk_level(results['risk_score'])
        results['recommendation'] = get_recommendation(results['risk_level'])
        results['cached'] = False
        
        # Cache the result for faster future lookups
        if len(url_analysis_cache) >= MAX_CACHE_SIZE:
            # Remove first item if cache is full
            url_analysis_cache.pop(next(iter(url_analysis_cache)))
        url_analysis_cache[cache_key] = results.copy()
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def analyze_url_structure(url, domain):
    """Analyze the URL structure for suspicious patterns."""
    issues = []
    
    # Check for IP address instead of domain
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.match(ip_pattern, domain):
        issues.append('URL uses IP address instead of domain name')
    
    # Check for excessive subdomains
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        issues.append(f'Excessive subdomains detected ({subdomain_count})')
    
    # Check for URL length
    if len(url) > 100:
        issues.append('Unusually long URL')
    
    # Check for suspicious characters
    if '@' in url:
        issues.append('URL contains @ symbol (potential credential harvesting)')
    
    # Check for encoded characters
    if '%' in url:
        issues.append('URL contains encoded characters')
    
    # Check for non-standard ports
    parsed = urlparse(url)
    if parsed.port and parsed.port not in [80, 443]:
        issues.append(f'Non-standard port detected: {parsed.port}')
    
    return {
        'status': 'warning' if issues else 'safe',
        'issues': issues,
        'message': f'{len(issues)} issue(s) found' if issues else 'URL structure looks normal'
    }


def check_ssl_certificate(domain):
    """Check if the domain has a valid SSL certificate."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days
                
                if days_until_expiry < 0:
                    return {'status': 'danger', 'message': 'SSL certificate has expired', 'valid': False}
                elif days_until_expiry < 30:
                    return {'status': 'warning', 'message': f'SSL certificate expires in {days_until_expiry} days', 'valid': True}
                else:
                    return {'status': 'safe', 'message': 'Valid SSL certificate', 'valid': True, 'expires_in_days': days_until_expiry}
                    
    except ssl.SSLError as e:
        return {'status': 'danger', 'message': f'SSL error: {str(e)}', 'valid': False}
    except socket.timeout:
        return {'status': 'warning', 'message': 'Connection timeout while checking SSL', 'valid': None}
    except Exception as e:
        return {'status': 'warning', 'message': f'Could not verify SSL: {str(e)}', 'valid': None}


def check_domain_age(domain):
    """Check the age of the domain using WHOIS."""
    try:
        w = whois.whois(domain, timeout=2)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            # Handle timezone-aware datetimes by removing timezone info
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            
            age_days = (datetime.now() - creation_date).days
            age_years = age_days / 365
            
            if age_days < 30:
                return {
                    'status': 'danger',
                    'message': f'Domain is very new ({age_days} days old)',
                    'age_days': age_days,
                    'creation_date': creation_date.isoformat()
                }
            elif age_days < 180:
                return {
                    'status': 'warning',
                    'message': f'Domain is relatively new ({age_days} days old)',
                    'age_days': age_days,
                    'creation_date': creation_date.isoformat()
                }
            else:
                return {
                    'status': 'safe',
                    'message': f'Domain is {age_years:.1f} years old',
                    'age_days': age_days,
                    'creation_date': creation_date.isoformat()
                }
        else:
            return {'status': 'warning', 'message': 'Could not determine domain age'}
            
    except Exception as e:
        return {'status': 'warning', 'message': f'WHOIS lookup failed: {str(e)}'}


def detect_typosquatting(domain):
    """Detect if the domain might be typosquatting a legitimate brand."""
    domain_lower = domain.lower()
    suspicious_matches = []
    
    # Remove common TLDs for comparison
    domain_base = domain_lower.split('.')[0]
    
    for legit_domain in LEGITIMATE_DOMAINS:
        legit_base = legit_domain.split('.')[0]
        
        # Check for similar domain names (Levenshtein-like check)
        similarity = calculate_similarity(domain_base, legit_base)
        
        if similarity > 0.7 and domain_lower != legit_domain:
            suspicious_matches.append({
                'legitimate_domain': legit_domain,
                'similarity': round(similarity * 100, 1)
            })
    
    if suspicious_matches:
        return {
            'status': 'danger',
            'message': 'Possible typosquatting detected',
            'matches': suspicious_matches
        }
    else:
        return {
            'status': 'safe',
            'message': 'No typosquatting detected'
        }


def calculate_similarity(s1, s2):
    """Calculate similarity between two strings."""
    # Simple character-based similarity
    if not s1 or not s2:
        return 0
    
    # Check for substring match
    if s1 in s2 or s2 in s1:
        return 0.8
    
    # Character overlap
    set1, set2 = set(s1), set(s2)
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    
    return intersection / union if union > 0 else 0


def check_suspicious_keywords(url):
    """Check URL for suspicious keywords commonly used in phishing."""
    url_lower = url.lower()
    found_keywords = []
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            found_keywords.append(keyword)
    
    if len(found_keywords) >= 3:
        return {
            'status': 'danger',
            'message': 'Multiple suspicious keywords detected',
            'keywords': found_keywords
        }
    elif found_keywords:
        return {
            'status': 'warning',
            'message': 'Suspicious keyword(s) detected',
            'keywords': found_keywords
        }
    else:
        return {
            'status': 'safe',
            'message': 'No suspicious keywords detected'
        }


def check_virustotal(url):
    """Check URL against VirusTotal database."""
    try:
        import base64
        import time
        
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        
        # Create URL ID (base64 encoded URL without padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        
        # Step 1: Try to get existing report first (faster for known URLs)
        existing_response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers,
            timeout=10
        )
        
        if existing_response.status_code == 200:
            # URL already analyzed - use cached results
            data = existing_response.json()['data']['attributes']
            stats = data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious > 0:
                return {
                    'status': 'danger',
                    'message': f'{malicious} security vendors flagged this URL as malicious',
                    'stats': stats
                }
            elif suspicious > 0:
                return {
                    'status': 'warning',
                    'message': f'{suspicious} security vendors flagged this URL as suspicious',
                    'stats': stats
                }
            else:
                return {
                    'status': 'safe',
                    'message': 'No security vendors flagged this URL',
                    'stats': stats
                }
        
        # Step 2: URL NOT in VirusTotal database - this is SUSPICIOUS
        # Legitimate popular sites are always in VT database
        # New/unknown URLs are often malicious
        
        # Submit for scan anyway
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data={'url': url},
            timeout=10
        )
        
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            
            # Poll for results (wait up to 10 seconds with longer intervals)
            for attempt in range(2):
                time.sleep(3)  # Wait 3 seconds between attempts
                
                result_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers,
                    timeout=10
                )
                
                if result_response.status_code == 200:
                    data = result_response.json()['data']['attributes']
                    scan_status = data.get('status', '')
                    
                    if scan_status == 'completed':
                        stats = data.get('stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        
                        if malicious > 0:
                            return {
                                'status': 'danger',
                                'message': f'{malicious} security vendors flagged this URL as malicious',
                                'stats': stats
                            }
                        elif suspicious > 0:
                            return {
                                'status': 'warning',
                                'message': f'{suspicious} security vendors flagged this URL as suspicious',
                                'stats': stats
                            }
                        else:
                            return {
                                'status': 'safe',
                                'message': 'No security vendors flagged this URL',
                                'stats': stats
                            }
            
            # Scan didn't complete in time - URL is NEW and UNKNOWN
            # This is suspicious - legitimate sites are usually already scanned
            return {
                'status': 'warning',
                'message': 'URL is new/unknown to VirusTotal (not in database) - treat with caution',
                'stats': {}
            }
        
        return {'status': 'warning', 'message': 'Could not complete VirusTotal check'}
        
    except Exception as e:
        return {'status': 'warning', 'message': f'VirusTotal check failed: {str(e)}'}


def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API."""
    try:
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
        
        payload = {
            'client': {
                'clientId': 'quishing-prevention',
                'clientVersion': '1.0.0'
            },
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            
            if 'matches' in result:
                threats = [match['threatType'] for match in result['matches']]
                return {
                    'status': 'danger',
                    'message': 'URL flagged by Google Safe Browsing',
                    'threats': threats
                }
            else:
                return {
                    'status': 'safe',
                    'message': 'URL not found in Google Safe Browsing threats database'
                }
        
        return {'status': 'warning', 'message': 'Could not complete Google Safe Browsing check'}
        
    except Exception as e:
        return {'status': 'warning', 'message': f'Google Safe Browsing check failed: {str(e)}'}


def calculate_risk_score(checks):
    """Calculate an overall risk score from 0-100."""
    score = 0
    weights = {
        'url_analysis': 8,
        'ssl_check': 10,
        'domain_age': 8,
        'typosquatting': 12,
        'suspicious_keywords': 7,
        'virustotal': 27,
        'google_safe_browsing': 28
    }
    
    # Check if either API flagged the URL as dangerous - if so, mark as high risk immediately
    vt_status = checks.get('virustotal', {}).get('status', 'safe')
    gsb_status = checks.get('google_safe_browsing', {}).get('status', 'safe')
    
    if vt_status == 'danger' or gsb_status == 'danger':
        # If either API flags as malicious, return high risk score immediately
        return 80
    
    if vt_status == 'warning' or gsb_status == 'warning':
        # If either API flags as suspicious, add significant penalty
        score += 35
    
    for check_name, weight in weights.items():
        if check_name in checks:
            # Skip API checks as we've already handled them above
            if check_name in ['virustotal', 'google_safe_browsing']:
                continue
            status = checks[check_name].get('status', 'safe')
            if status == 'danger':
                score += weight
            elif status == 'warning':
                score += weight * 0.5
    
    return min(100, int(score))


def get_risk_level(score):
    """Get risk level based on score."""
    if score >= 60:
        return 'high'
    elif score >= 30:
        return 'medium'
    else:
        return 'low'


def get_recommendation(risk_level):
    """Get recommendation based on risk level."""
    recommendations = {
        'high': 'DANGER: This URL shows multiple signs of being malicious. Do NOT proceed!',
        'medium': 'CAUTION: This URL has some suspicious characteristics. Proceed with extreme caution.',
        'low': 'This URL appears to be relatively safe, but always stay vigilant.'
    }
    return recommendations.get(risk_level, 'Unable to determine safety.')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
