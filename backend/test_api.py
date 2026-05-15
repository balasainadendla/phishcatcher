"""
Test script for PhishCatcher API
"""

import requests
import json

def test_health():
    """Test health endpoint"""
    print("\n🔍 Testing /health endpoint...")
    try:
        response = requests.get('http://localhost:5000/health')
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_predict_phishing():
    """Test prediction with phishing features"""
    print("\n🔍 Testing /predict with PHISHING features...")
    
    # Phishing-like features
    features = [
        150,  # url_length (long)
        1,    # has_at_symbol
        8,    # num_dots (many)
        0,    # is_https (not secure)
        5,    # num_hyphens
        1,    # has_ip_address
        3,    # num_suspicious_keywords
        10,   # num_input_fields
        1,    # has_password_field
        1,    # form_action_mismatch
        20,   # num_external_links
        1,    # has_hidden_fields
        2,    # num_iframes
        4.2,  # url_entropy
        30    # domain_age_days (very new)
    ]
    
    try:
        response = requests.post(
            'http://localhost:5000/predict',
            json={'features': features},
            headers={'Content-Type': 'application/json'}
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_predict_legitimate():
    """Test prediction with legitimate features"""
    print("\n🔍 Testing /predict with LEGITIMATE features...")
    
    # Legitimate-like features
    features = [
        45,   # url_length (short)
        0,    # has_at_symbol
        2,    # num_dots (few)
        1,    # is_https (secure)
        1,    # num_hyphens
        0,    # has_ip_address
        0,    # num_suspicious_keywords
        3,    # num_input_fields
        1,    # has_password_field
        0,    # form_action_mismatch
        5,    # num_external_links
        0,    # has_hidden_fields
        0,    # num_iframes
        2.5,  # url_entropy
        1200  # domain_age_days (old domain)
    ]
    
    try:
        response = requests.post(
            'http://localhost:5000/predict',
            json={'features': features},
            headers={'Content-Type': 'application/json'}
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_model_info():
    """Test model info endpoint"""
    print("\n🔍 Testing /model/info endpoint...")
    try:
        response = requests.get('http://localhost:5000/model/info')
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("  PHISHCATCHER API TESTS")
    print("="*60)
    
    tests = [
        ("Health Check", test_health),
        ("Phishing Detection", test_predict_phishing),
        ("Legitimate Detection", test_predict_legitimate),
        ("Model Info", test_model_info)
    ]
    
    results = []
    for test_name, test_func in tests:
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "="*60)
    print("  TEST RESULTS")
    print("="*60)
    for test_name, result in results:
        status = "✓ PASSED" if result else "❌ FAILED"
        print(f"{test_name:30s} {status}")
    print("="*60 + "\n")

if __name__ == '__main__':
    main()