import re

def analyze_writing_patterns(message: str):
    warnings = []
    pattern_score = 0

    letters = [char for char in message if char.isalpha()]
    if letters:
        uppercase_count = sum(char.isupper() for char in letters)
        uppercase_ratio = uppercase_count / len(letters)

        if uppercase_ratio > 0.55 and len(letters) > 10:
            pattern_score += 1
            warnings.append("Message uses an unusually high amount of capital letters")

    if re.findall(r"[!?]{3,}", message):
        pattern_score += 1
        warnings.append("Message uses excessive punctuation (multiple exclamation or question marks)")

    words = re.findall(r"\b\w+\b", message.lower())
    repeated_words = [
        words[i] for i in range(len(words) - 1)
        if words[i] == words[i + 1] and len(words[i]) > 2
    ]

    if repeated_words:
        pattern_score += 1
        warnings.append(f"Message contains repeated words: {', '.join(set(repeated_words))}")

    return pattern_score, warnings