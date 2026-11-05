import re


def analyze_writing_patterns(message):
    warnings = []
    pattern_score = 0

    # Check for excessive capital letters
    letters = [char for char in message if char.isalpha()]

    if letters:
        uppercase_count = sum(char.isupper() for char in letters)
        uppercase_ratio = uppercase_count / len(letters)

        if uppercase_ratio > 0.6 and len(letters) > 10:
            pattern_score += 1
            warnings.append("Message uses an unusually high amount of capital letters")

    # Check for excessive punctuation
    punctuation_matches = re.findall(r"[!?]{3,}", message)

    if punctuation_matches:
        pattern_score += 1
        warnings.append("Message uses excessive punctuation")

    # Check for repeated words
    words = re.findall(r"\b\w+\b", message.lower())

    repeated_words = []

    for index in range(len(words) - 1):
        if words[index] == words[index + 1]:
            repeated_words.append(words[index])

    if repeated_words:
        pattern_score += 1
        warnings.append(
            "Message contains repeated words: "
            + ", ".join(set(repeated_words))
        )

    return pattern_score, warnings