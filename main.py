from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import math
import joblib
from collections import Counter
from xgboost import XGBRegressor

# Initialize FastAPI app
app = FastAPI()

# Load XGBoost model
model = XGBRegressor()
model.load_model('password_strength_model.json')

# QWERTY keyboard adjacency map
qwerty_adjacency = {
    '1':'2q', '2':'1qw3', '3':'2we4', '4':'3er5', '5':'4rt6',
    '6':'5ty7', '7':'6yu8', '8':'7ui9', '9':'8io0', '0':'9op',
    'q':'12wa', 'w':'23qeas', 'e':'34wrds', 'r':'45etdf',
    't':'56ryfg', 'y':'67tuhg', 'u':'78yijh', 'i':'89uokj',
    'o':'90ipkl', 'p':'0ol', 'a':'qwsz', 's':'awsxed',
    'd':'esxwrc', 'f':'rtdcvg', 'g':'tyfvhb', 'h':'uygbjn',
    'j':'uihknm', 'k':'iojlm', 'l':'opk', 'z':'asx',
    'x':'zsdce', 'c':'xdfv', 'v':'fcgb', 'b':'vghn',
    'n':'bhjm', 'm':'njk'
}

# Load leaked passwords
try:
    with open('rockyou.txt', 'r', encoding='latin-1') as f:
        leaked_passwords = set(line.strip() for line in f)
except FileNotFoundError:
    leaked_passwords = {'password', '123456', 'qwerty', 'abc123'}

# Time-to-crack estimation table (in seconds)
time_to_crack_table = [
    (1, 'Instantly'),
    (10**3, 'Seconds'),
    (10**4, 'Minutes'),
    (10**6, 'Hours'),
    (10**8, 'Days'),
    (10**10, 'Years'),
    (10**12, 'Centuries'),
]

def estimate_time_to_crack(score):
    base_time = 10 ** (score / 10)
    for threshold, label in time_to_crack_table:
        if base_time < threshold:
            return f'{base_time:.2f} {label}'
    return f'{base_time:.2f} Millennia'

# Helper functions
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
    freq = Counter(password)
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
    if score < 30: return "Very Weak"
    elif score < 50: return "Weak"
    elif score < 70: return "Medium"
    elif score < 85: return "Strong"
    else: return "Very Strong"

# Request Body Model
class PasswordRequest(BaseModel):
    password: str

# API Endpoints
@app.post('/analyze_password/')
def analyze_password(request: PasswordRequest):
    password = request.password
    features = extract_features(password)
    features_df = pd.DataFrame([features])

    score = int(model.predict(features_df)[0])
    score = max(0, min(100, score))
    category = strength_category(score)
    time_to_crack = estimate_time_to_crack(score)

    return {
        'password': password,
        'score': score,
        'strength_category': category,
        'time_to_crack': time_to_crack,
        'features': features
    }

@app.get('/')
def read_root():
    return {'message': 'Welcome to the Password Strength Analyzer API'}
