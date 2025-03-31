from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
from xgboost import XGBRegressor
import json
import math
from collections import Counter

app = FastAPI()

# Load model
model = XGBRegressor()
model.load_model('password_strength_model.json')


# Pydantic model for request body
class PasswordInput(BaseModel):
    password: str


class PasswordResponse(BaseModel):
    password: str
    strength: str
    score: int
    features: dict


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
@app.post("/analyze-password", response_model=PasswordResponse)
async def analyze_password(input_data: PasswordInput):
    password = input_data.password
    if not password:
        raise HTTPException(status_code=400, detail="Password cannot be empty.")

    features = extract_features(password)
    features_df = pd.DataFrame([features])
    score = int(model.predict(features_df)[0])
    score = max(0, min(100, score))
    category = strength_category(score)

    return PasswordResponse(
        password=password,
        strength=category,
        score=score,
        features=features
    )

# To run: uvicorn password_strength_api:app --reload
