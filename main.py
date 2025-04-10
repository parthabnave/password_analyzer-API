from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import math
from collections import Counter
from xgboost import XGBRegressor
import sys

app = FastAPI()

# Load XGBoost model
try:
    model = XGBRegressor()
    model.load_model('password_strength_model.json')
except Exception as e:
    print(f"Error loading XGBoost model: {e}")
    sys.exit(1)

# QWERTY adjacency map
qwerty_adjacency = {
    '1': '2q', '2': '1qw3', '3': '2we4', '4': '3er5', '5': '4rt6',
    '6': '5ty7', '7': '6yu8', '8': '7ui9', '9': '8io0', '0': '9op',
    'q': '12wa', 'w': '23qeas', 'e': '34wrds', 'r': '45etdf',
    't': '56ryfg', 'y': '67tuhg', 'u': '78yijh', 'i': '89uokj',
    'o': '90ipkl', 'p': '0ol', 'a': 'qwsz', 's': 'awsxed',
    'd': 'esxwrc', 'f': 'rtdcvg', 'g': 'tyfvhb', 'h': 'uygbjn',
    'j': 'uihknm', 'k': 'iojlm', 'l': 'opk', 'z': 'asx',
    'x': 'zsdce', 'c': 'xdfv', 'v': 'fcgb', 'b': 'vghn',
    'n': 'bhjm', 'm': 'njk'
}

# Load leaked passwords
try:
    with open('rockyou.txt', 'r', encoding='latin-1') as f:
        leaked_passwords = set(line.strip() for line in f)
except FileNotFoundError:
    leaked_passwords = {'password', '123456', 'qwerty', 'abc123'}

def estimate_time_to_crack(features):
    password_length = features['length']
    has_upper = features['upper'] > 0
    has_lower = features['lower'] > 0
    has_digits = features['digits'] > 0
    has_special = features['special'] > 0

    if features['is_leaked'] == 1:
        return {
            'bcrypt': 'Instantly (password is compromised)',
            'sha256': 'Instantly (password is compromised)'
        }

    char_set_size = 0
    if has_lower:
        char_set_size += 26
    if has_upper:
        char_set_size += 26
    if has_digits:
        char_set_size += 10
    if has_special:
        char_set_size += 33  
    if char_set_size == 0:
        char_set_size = 26

    entropy_reduction = 0
    if features['proximity'] > password_length * 0.5:
        entropy_reduction += 2
    if features['repeats'] > 3:
        entropy_reduction += features['repeats'] / 2
    if features['sequential'] > 2:
        entropy_reduction += features['sequential'] / 2

    effective_length = max(1, password_length - entropy_reduction)
    entropy_bits = effective_length * math.log2(char_set_size)

    hash_speeds = {
        'bcrypt': 10**4,      # 10,000 attempts per second
        'sha256': 10**8       # 100 million attempts per second
    }

    possible_combinations = 2 ** entropy_bits
    average_attempts = possible_combinations / 2
    result = {}

    for algorithm, speed in hash_speeds.items():
        seconds_to_crack = average_attempts / speed

        if seconds_to_crack < 1:
            result[algorithm] = 'Instantly'
        elif seconds_to_crack < 60:
            result[algorithm] = f'{seconds_to_crack:.2f} seconds'
        elif seconds_to_crack < 3600:
            result[algorithm] = f'{seconds_to_crack/60:.2f} minutes'
        elif seconds_to_crack < 86400:
            result[algorithm] = f'{seconds_to_crack/3600:.2f} hours'
        elif seconds_to_crack < 86400*365:
            result[algorithm] = f'{seconds_to_crack/86400:.2f} days'
        elif seconds_to_crack < 86400*365*100:
            result[algorithm] = f'{seconds_to_crack/(86400*365):.2f} years'
        elif seconds_to_crack < 86400*365*1000:
            result[algorithm] = f'{seconds_to_crack/(86400*365*100):.2f} centuries'
        else:
            result[algorithm] = f'{seconds_to_crack/(86400*365*1000):.2f} millennia'

    return result

def keyboard_proximity(password):
    distance = 0
    for i in range(len(password) - 1):
        if password[i+1] in qwerty_adjacency.get(password[i].lower(), ''):
            distance += 1
    return distance

def repeated_substring_count(password):
    n = len(password)
    lps = [0] * n
    length = 0
    i = 1
    while i < n:
        if password[i] == password[length]:
            length += 1
            lps[i] = length
            i += 1
        else:
            if length != 0:
                length = lps[length - 1]
            else:
                lps[i] = 0
                i += 1
    return max(lps)

def conditional_entropy(password):
    bigrams = [password[i:i+2] for i in range(len(password) - 1)]
    bigram_counts = Counter(bigrams)
    total_bigrams = sum(bigram_counts.values())
    entropy = -sum((count / total_bigrams) * math.log2(count / total_bigrams) for count in bigram_counts.values())
    return round(entropy, 2)

def extract_features(password):
    length = len(password)
    entropy = conditional_entropy(password)
    upper = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())
    repeats = repeated_substring_count(password)
    sequential = sum(1 for i in range(length-1) if ord(password[i+1]) - ord(password[i]) == 1)
    proximity = keyboard_proximity(password)
    is_leaked = 1 if password in leaked_passwords else 0

    return {
        'length': length,
        'entropy': entropy,
        'upper': upper,
        'lower': lower,
        'digits': digits,
        'special': special,
        'repeats': repeats,
        'sequential': sequential,
        'proximity': proximity,
        'is_leaked': is_leaked,
    }

def strength_category(score):
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Medium"
    elif score < 85:
        return "Strong"
    else:
        return "Very Strong"

def analyze_password_logic(password: str):
    features = extract_features(password)
    features_df = pd.DataFrame([features])
    score = int(model.predict(features_df)[0])
    score = max(0, min(100, score))
    category = strength_category(score)
    time_estimates = estimate_time_to_crack(features)
    return {
        'password': password,
        'score': score,
        'strength_category': category,
        'time_to_crack': time_estimates,
        'features': features
    }

def generate_suggestions(analysis):
    features = analysis['features']
    score = analysis['score']
    suggestions = []

    # Heuristic rules for suggestions
    if features['length'] < 8:
        suggestions.append("Increase the password length to at least 8 characters for better security.")
    if features['upper'] == 0:
        suggestions.append("Add at least one uppercase letter to improve complexity.")
    if features['lower'] == 0:
        suggestions.append("Include at least one lowercase letter for variety.")
    if features['digits'] == 0:
        suggestions.append("Add at least one digit to enhance strength.")
    if features['special'] == 0:
        suggestions.append("Incorporate at least one special character (e.g., !, @, #) for added security.")
    if features['repeats'] > 2:
        suggestions.append("Reduce repeated patterns or substrings to make it harder to guess.")
    if features['sequential'] > 1:
        suggestions.append("Avoid sequential characters (e.g., 'abc' or '123') to increase randomness.")
    if features['proximity'] > features['length'] * 0.5:
        suggestions.append("Minimize the use of adjacent keyboard keys (e.g., 'qwerty') for better randomness.")
    if features['is_leaked'] == 1:
        suggestions.append("This password is in a known leak database; choose a unique one.")
    if score < 50 and not suggestions:
        suggestions.append("Your password is weak; consider making it longer and more diverse.")
    elif score < 70 and not suggestions:
        suggestions.append("Your password is moderately strong; add more variety to improve it.")
    elif not suggestions:
        suggestions.append("Your password is strong; maintain its complexity.")

    return suggestions

def apply_leetspeak(password):
    leetspeak_dict = {
        'a': '4', 'b': '8', 'e': '3', 'g': '6', 'i': '1', 'o': '0', 's': '5', 't': '7', 'z': '2'
    }
    new_password = ''.join(leetspeak_dict.get(c, c) if c.islower() else c for c in password)
    return new_password

class PasswordRequest(BaseModel):
    password: str

@app.post('/analyze_password/')
def analyze_password(request: PasswordRequest):
    return analyze_password_logic(request.password)

def improve_password_score(password):
    improved_password = apply_leetspeak(password)
    
    # Ensure the improved password has a good score
    while True:
        analysis = analyze_password_logic(improved_password)
        if analysis['score'] >= 70:
            break
        
        # Apply modifications to enhance security
        if analysis['features']['length'] < 12:
            improved_password += '!@'
        if analysis['features']['upper'] == 0:
            improved_password = improved_password[:2] + 'A' + improved_password[2:]
        if analysis['features']['digits'] == 0:
            improved_password += '7'
        if analysis['features']['special'] == 0:
            improved_password += '#'
        
    return improved_password

@app.post('/improve_password/')
def improve_password(request: PasswordRequest):
    password = request.password
    
    # Analyze the original password
    original_analysis = analyze_password_logic(password)
    
    # Generate heuristic suggestions
    suggestions = generate_suggestions(original_analysis)
    
    # Generate and analyze an improved password
    improved_password = improve_password_score(password)
    improved_analysis = analyze_password_logic(improved_password)
    
    # Return all information
    return {
        "original_analysis": original_analysis,
        "suggestions": suggestions,
        "improved_password": improved_password,
        "improved_analysis": improved_analysis
    }


@app.get('/')
def read_root():
    return {'message': 'Welcome to the Password Strength Analyzer API'}
