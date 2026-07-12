SEVERITY_BANDS = ((90, "Critical"), (60, "High"), (30, "Medium"), (0, "Low"))


def severity_for_score(score: int) -> str:
    for threshold, severity in SEVERITY_BANDS:
        if score >= threshold:
            return severity
    return "Low"
