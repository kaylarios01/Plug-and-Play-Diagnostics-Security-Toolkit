import os

def test_password_strength(user_password):
    findings = []
    score_deduction = 0
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rockyou_path = os.path.join(base_dir, "data", "rockyou.txt")
    
    if not os.path.exists(rockyou_path):
        return 0, ["RockYou list not found. Skipping test."]

    try:
        with open(rockyou_path, 'r', encoding='latin-1') as f:
            for line in f:
                if user_password.strip() == line.strip():
                    findings.append("Our password was found in a list of leaked passwords!")
                    score_deduction = 30
                    break
    except Exception as e:
        findings.append(f"Password test error: {str(e)}")
        
    return score_deduction, findings
