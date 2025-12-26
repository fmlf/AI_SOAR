import sys
import os

# [1. 버전 호환성 패치]
try:
    if sys.version_info < (3, 10):
        import importlib
        import importlib_metadata
        importlib.metadata = importlib_metadata
except ImportError:
    pass

import gzip
import csv
import json
import urllib.request
import ssl
import certifi 
import google.generativeai as genai

# --- [설정] ---
config_path = "/opt/splunk/bin/scripts/secrets.json"
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
    my_key = config.get('google_api_key')
    DISCORD_WEBHOOK_URL = config.get('discord_webhook').strip()
    
except Exception as e:
    # 설정 파일 없으면 그냥 하드코딩 된 값 쓰거나 종료 (테스트용)
    print(f"설정 로드 실패: {e}", file=sys.stderr)
    sys.exit(1)

genai.configure(api_key=my_key)
model = genai.GenerativeModel('gemini-2.0-flash')
PENDING_FILE = "/opt/splunk/bin/scripts/pending_fix.sh"

def ask_gemini_smart(log_summary, log_sample, attack_count):
    # ★ 여기가 핵심: 단순 분석이 아니라 "상황 판단"을 시킵니다 ★
    prompt = f"""
    You are a 'Cyber Security AI Engine'.
    
    [Current Situation Report]
    - Detected Log Sample: "{log_sample}"
    - Frequency (Count): {attack_count} times.

    [Mission]
    Analyze the log and generate the EXACT Linux command to handle the situation.

    [Decision Logic & Safety Protocol]
    1. ANALYZE THREAT:
       - Is this a Brute Force or Login Failure attack? (Keywords: Failed password, Invalid user, Login failed)
       - Is the Frequency high (>3)?

    2. EXTRACT & CHECK IP (Crucial Step):
       - Extract the source IP address.
       - CHECK: Is it a Private/Internal IP? 
         (Ranges: 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16.x.x, 203.230.x.x)
       
    3. DETERMINE ACTION:
       - CASE A [Private IP detected]: 
         DO NOT BLOCK. 
         Output: echo "⚠️ Safety Lock: Internal IP detected. No block applied."
       
      - CASE B [Public/Attacker IP detected]: 
         Generate a Cisco ASA blocking command using 'shun'.    
         Command Template: shun IP_ADDRESS
       
       - CASE C [System Error / Config Issue]:
         Generate an echo or sed command to fix/log it.
       
       - CASE D [False Alarm / Low Threat]:
         Output: echo "No action needed."

    [Output Rules]
    - Respond ONLY with the raw command string.
    - NO markdown formatting (no ```bash ... ```).
    - NO explanations.
    """
    try:
        response = model.generate_content(prompt)
        clean_cmd = response.text.replace("```bash", "").replace("```", "").strip()
        return clean_cmd
    except Exception as e:
        return f"echo 'AI Error: {e}'"

def send_discord(cmd, log_preview, attack_count):
    # 공격 횟수에 따라 제목 색상과 멘트 변경
    if attack_count > 5:
        title = "🚨 [심각] 공격 징후 예측 및 차단 대기"
        color = 15158332 # 빨간색
        desc = f"⚠️ **{attack_count}회**의 반복적인 실패가 감지되었습니다.\nAI가 **Brute Force** 공격으로 예측하고 차단을 제안합니다."
    else:
        title = "🛡️ 보안/설정 조치 제안"
        color = 3066993  # 초록색
        desc = "AI가 로그를 분석하고 대응 명령어를 생성했습니다."

    data = {
        "username": "AI Security Manager",
        "embeds": [{
            "title": title,
            "description": desc,
            "color": color, 
            "fields": [
                {"name": "📊 상황 요약", "value": f"로그 샘플: `{log_preview[:60]}...`\n발생 횟수: **{attack_count}회**", "inline": False},
                {"name": "🤖 AI 제안 명령어", "value": f"```bash\n{cmd}\n```", "inline": False},
                {"name": "✅ 승인 실행", "value": "`sudo python3 /opt/splunk/bin/scripts/approve.py`", "inline": False},
            ]
        }]
    }
    
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    req = urllib.request.Request(
        DISCORD_WEBHOOK_URL, 
        data=json.dumps(data).encode('utf-8'), 
        headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
    )
    urllib.request.urlopen(req, context=ssl_context)

if __name__ == "__main__":
    
    try:
        log_sample = "No Data"
        attack_count = 0
        is_security_threat = False
       

        if len(sys.argv) < 9:
            # 테스트 모드
            log_sample = "Failed password for root from 192.168.0.50 port 22 ssh2"
            attack_count = 10 # 10번 틀렸다고 가정
        else:
            results_file = sys.argv[8]
            try:
                with gzip.open(results_file, 'rt') as f:
                    reader = csv.DictReader(f)
                    
                    # [핵심 로직] CSV를 한 줄씩 읽으면서 중요한 로그를 찾아냄
                    for row in reader:
                        if '_raw' in row:
                            raw = row['_raw']
                            
                            # 1. 공격 로그 카운팅 (예측을 위한 데이터 수집)
                            if "Failed password" in raw or "Invalid user" in raw or "Login failed" in raw or "LOGIN_FAILED" in raw:
                                attack_count += 1
                                log_sample = raw # 공격 로그를 최우선 샘플로 잡음
                                is_security_threat = True
                            
                            # 2. 공격 로그가 아직 안 나왔으면, 일반 로그라도 잡아둠
                            elif not is_security_threat:
                                log_sample = raw
                                
            except Exception as read_err:
                print(f"Log Read Error: {read_err}", file=sys.stderr)

        # 로그가 아예 없으면 종료
        if log_sample == "No Data":
            sys.exit(0)

        # 1. 똑똑해진 AI에게 물어보기 (횟수 정보까지 같이 줌)
        fix_command = ask_gemini_smart("Summary", log_sample, attack_count)

        # 2. 명령어 파일 저장
        with open(PENDING_FILE, "w") as f:
            f.write(fix_command)
        os.chmod(PENDING_FILE, 0o755)

        # 3. 디스코드 알림 (필요없는 잡로그는 무시)
        if "No action" not in fix_command:
            send_discord(fix_command, log_sample, attack_count)
            print(f"AI Decision: {fix_command}")
        else:
            print("AI Decision: No Action Needed")
            
    except Exception as e:
        print(f"Critical Error: {e}", file=sys.stderr)
        
        # 2. 명령어 파일 저장 (중요 명령어 덮어쓰기 방지 로직 추가)
        should_write = True
        
        # 이미 대기 중인 파일이 있는지 확인
        if os.path.exists(PENDING_FILE):
            with open(PENDING_FILE, "r") as f:
                existing_cmd = f.read()
            
            # 대기 중인 명령어가 '차단(shun, firewall)' 관련이고, 
            # 새로 온 명령어가 '별거 아님(No action, echo)'이라면 -> 덮어쓰지 않음!
            if ("shun" in existing_cmd or "firewall" in existing_cmd) and "No action" in fix_command:
                print("⚠️ Critical command pending. Skipping overwrite.")
                should_write = False

        if should_write:
            with open(PENDING_FILE, "w") as f:
                f.write(fix_command)
            os.chmod(PENDING_FILE, 0o755)
