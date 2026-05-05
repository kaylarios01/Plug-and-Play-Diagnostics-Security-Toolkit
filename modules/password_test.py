import os

def test_password_strength(user_password):
    findings = []
    score_deduction = 0
    
    # Get path to rockyou.txt
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rockyou_path = os.path.join(base_dir, "data", "rockyou.txt")
    
    if not os.path.exists(rockyou_path):
        return 0, ["Database missing. Skipping leak check."]

    try:
        with open(rockyou_path, 'r', encoding='latin-1') as f:
            # We only check the first 100,000 lines to keep the UI fast
            for i, line in enumerate(f):
                if i > 100000: break 
                if user_password.strip() == line.strip():
                    findings.append("CRITICAL: Password found in RockYou leak list!")
                    score_deduction = 50
                    return score_deduction, findings
    except Exception as e:
        return 0, [f"Test error: {str(e)}"]
        
    return score_deduction, findings
