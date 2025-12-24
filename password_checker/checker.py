"""Password strength checking logic."""

import re
import math
from collections import Counter


COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "welcome", "admin", "login", "princess", "solo",
    "starwars", "password123", "123456789", "12345", "1234567890"
}


def calculate_entropy(password):
    if not password:
        return 0.0

    char_counts = Counter(password)
    length = len(password)

    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    entropy_bits = entropy * length

    return entropy_bits


def check_password_strength(password):
    score = 0
    feedback = []

    # Check if password is blacklisted but continue with analysis
    is_blacklisted = password.lower() in COMMON_PASSWORDS

    length = len(password)
    entropy = calculate_entropy(password)

    if length < 8:
        feedback.append("Password should be at least 8 characters long")
    else:
        score += min(length * 2, 25)

    entropy_score = min(int(entropy * 1.0), 35)
    score += entropy_score

    if re.search(r'[a-z]', password):
        score += 10
    else:
        feedback.append("Add lowercase letters")

    if re.search(r'[A-Z]', password):
        score += 10
    else:
        feedback.append("Add uppercase letters")

    if re.search(r'\d', password):
        score += 10
    else:
        feedback.append("Add numbers")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 15
    else:
        feedback.append("Add special characters")

    if length >= 12:
        score += 10

    if entropy < 30:
        feedback.append("Password has low entropy - try more varied characters")
    elif entropy > 50:
        feedback.append("Good entropy - password has high randomness")

    if score >= 80:
        strength = "Strong"
    elif score >= 60:
        strength = "Moderate"
    elif score >= 40:
        strength = "Weak"
    else:
        strength = "Very Weak"

    # Override score and strength for blacklisted passwords
    if is_blacklisted:
        feedback.insert(0, "This password appears in common leaked password lists - DO NOT USE")
        score = 0
        strength = "Very Weak"
        entropy = 0.0

    return {
        "score": min(score, 100),
        "strength": strength,
        "feedback": feedback,
        "entropy": round(entropy, 2),
        "is_blacklisted": is_blacklisted
    }
