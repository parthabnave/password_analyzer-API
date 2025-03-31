from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import math
from collections import Counter

app = FastAPI()


# Pydantic model for request body
class PasswordInput(BaseModel):
    password: str


# Utility Functions (Reusing from previous implementation)
def extract_features(password):
    length = len(password)
    freq = Counter(password)

    # Shannon Entropy
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values() if count > 0)

    upper = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())

    repeats = length - len(set(password))
    sequential = sum(1 for i in range(length - 1) if ord(password[i + 1]) - ord(password[i]) == 1)

    # Leaked Password Check (Dummy Example)
    is_leaked = 1 if password in {'password', '123456', 'qwerty', 'abc123'} else 0

    return {
        'length': length,
        'entropy': round(entropy, 2),
        'upper': upper,
        'lower': lower,
        'digits': digits,
        'special': special,
        'repeats': repeats,
        'sequential': sequential,
        'is_leaked': is_leaked,
    }


def calculate_rule_based_score(features):
    score = (
            features['length'] * 2 +
            features['entropy'] * 10 +
            (features['upper'] + features['digits'] + features['special']) * 5 -
            features['repeats'] * 3 -
            features['sequential'] * 2 -
            features['is_leaked'] * 30
    )
    return max(0, min(100, int(score)))


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


# API Endpoint
@app.post("/analyze-password")
async def analyze_password(input_data: PasswordInput):
    password = input_data.password
    if not password:
        raise HTTPException(status_code=400, detail="Password cannot be empty.")

    features = extract_features(password)
    score = calculate_rule_based_score(features)
    category = strength_category(score)

    return {
        "password": password,
        "strength": category,
        "score": score,
        "features": features
    }

# To run: uvicorn main:app --reload
