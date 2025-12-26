import os 
import sys #파일 읽기삭제, 시스템 종료 사용
import json #설정파일 읽기
import urllib.request #디스코드로 메시지 전송
import datetime 
import ssl #디스코드 통신 시 보안 인증서 에러 X
import certifi
import subprocess #리눅스 터미널 파이썬에서 실행
from netmiko import ConnectHandler #네크워크 장비에 파이썬 침투

# --- [설정 파일 읽기] ---
config_path = "/opt/splunk/bin/scripts/secrets.json" #API키, 비번 파일
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
     #필요 정보 변수에 담음
    DISCORD_WEBHOOK_URL = config.get('discord_webhook').strip()
    ASA_HOSTS = config.get('asa_hosts') 
    ASA_USER = config.get('asa_user')
    ASA_PASS = config.get('asa_pass')
    ASA_SECRET = config.get('asa_secret')
except Exception as e:
    print(f"⚠️ 설정 파일 오류: {e}")
    sys.exit(1)

PENDING_FILE = "/opt/splunk/bin/scripts/pending_fix.sh" #대기파일 위치

# --- [디스코드 전송 함수들] ---
def send_discord_payload(data):
    """실제 디스코드 전송을 담당하는 내부 함수"""
    if not DISCORD_WEBHOOK_URL: return
    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where()) #보안 인증서로 전송실패 막기
        req = urllib.request.Request( 
            DISCORD_WEBHOOK_URL, #webhook url을 가져옴
            data=json.dumps(data).encode('utf-8'), #파이썬의 딕셔너리 값을 json으로 변환, utf-8로 인코딩
            headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'} 
        )#바디 데이터의 값이 json이라는 걸 알려줌. 
        
        urllib.request.urlopen(req, context=ssl_context) #상대방의 SSL 인증서 검증
    except Exception as e:
        print(f"⚠️ 디스코드 전송 실패: {e}")

def send_discord_result(target_type, command, results, is_success):
    """결과(성공/실패) 알림 전송"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if is_success:
        title = f"✅ {target_type} 적용 성공"
        color = 5763719 # 초록색
    else:
        title = f"❌ {target_type} 적용 실패"
        color = 15548997 # 빨간색
    
    if isinstance(results, list): # ASA (여러 대)
        result_text = ""
        for res in results:
            icon = "✅" if res['success'] else "❌"
	            result_text += f"{icon} **{res['host']}**: {res['msg']}\n"#장비가 뱉은 msg 출력. host는 ip주소 
    else: # Linux (단일 문자열)
        result_text = f"```\n{results[:800]}\n```" #디코 글자제한으로 인한 800자까지 가져와라

    data = {
        "username": "Splunk AI Guard",
        "embeds": [{
            "title": title,
            "description": f"관리자 승인에 의해 **{target_type}** 명령어가 실행되었습니다.",
            "color": color,
            "fields": [
                {"name": "💻 실행된 명령어", "value": f"`{command}`", "inline": False},
                {"name": "📄 실행 결과", "value": result_text, "inline": False},
                {"name": "⏰ 실행 시간", "value": timestamp, "inline": True}
            ]
        }]
    }
    send_discord_payload(data) #메시지 보내는 양식

def send_discord_cancel(target_type, command):
    """취소 알림 전송"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")#시간 나타냄(실행시간)
    data = {
        "username": "Splunk AI Guard",
        "embeds": [{
            "title": f"🚫 {target_type} 작업 취소됨",
            "description": "관리자가 명령어 실행을 거부(취소)했습니다.",
            "color": 9807270, # 회색
            "fields": [
                {"name": "🗑️ 폐기된 명령어", "value": f"`{command}`", "inline": False},
                {"name": "⏰ 취소 시간", "value": timestamp, "inline": True}
            ]
        }]
    }
    send_discord_payload(data)

# --- [실행 함수들] ---
def execute_linux(command):
    print("\n🐧 [Linux] 시스템 명령어를 실행합니다...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print("✅ Linux 적용 완료!")      #터미널에 입력하는 것과 똑같이 실행  #실행결과 가져옴
        output = result.stdout if result.stdout else "Success (No Output)"#결과값 있으면 출력, 없으면 success 출력
        send_discord_result("Linux System", command, output, True)#Linux System 이라는 이름달고 output과 함꼐 true 출력
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr if e.stderr else str(e)
        print(f"❌ Linux 실행 실패: {err_msg}")
        send_discord_result("Linux System", command, err_msg, False) #실패 결과 전송

def execute_asa(command):
    print(f"\n🔥 [Cisco ASA] 총 {len(ASA_HOSTS)}대 장비에 적용합니다...")
    execution_results = []
    
    for host in ASA_HOSTS:
        print(f"🚀 [{host}] 접속 시도 중...")
        try:
            device_conf = {
                'device_type': 'cisco_asa',
                'host': host,
                'username': ASA_USER,
                'password': ASA_PASS,
                'secret': ASA_SECRET,
            }
            net_connect = ConnectHandler(**device_conf) #ssh 접속
            net_connect.enable() #en 입력함
            output = net_connect.send_command_timing(command)#명령 입력 후 결과 기다림
            net_connect.disconnect()#ssh 로그아웃
            
            # [요청하신 성공 메시지 출력]
            print(f"✅ [{host}] 방화벽에 설정 적용을 성공했습니다!")
            
            execution_results.append({'host': host, 'success': True, 'msg': "Success"})
        except Exception as e:
            print(f"❌ [{host}] 실패: {e}")
            execution_results.append({'host': host, 'success': False, 'msg': str(e)})
    
    is_success_all = any(r['success'] for r in execution_results)
    send_discord_result("Firewall Policy", command, execution_results, is_success_all)
#하나라도 성공하면 성공

# --- [메인 로직] ---
def main():
    if not os.path.exists(PENDING_FILE):
        print("❌ 승인 대기 중인 명령어가 없습니다.")
        return

    with open(PENDING_FILE, "r") as f:
        command = f.read().strip()

    # 자동 판단 로직
    is_firewall_cmd = command.startswith("shun") or command.startswith("no shun") or "access-list" in command
                       #명령어가 shun으로 시작하는가?       no shun으로 시작하는가?       #acl이 포함되는가?

    target_name = "Cisco ASA 방화벽" if is_firewall_cmd else "Linux 시스템 (Splunk)"
                    #위 조건 중 하나라도 해당되면 true -> cisco ASA 방화벽

    print("="*60)
    print(f"🚨 [승인 요청] 대상: {target_name}")
    print("="*60)
    print(f"명령어:\n{command}")
    print("="*60)

    try:
        choice = input("위 명령어를 실행하시겠습니까? (y/n): ").lower()
    except KeyboardInterrupt:
        choice = 'n'

    if choice == 'y':
        if is_firewall_cmd:
            execute_asa(command)
        else:
            execute_linux(command)
        
        if os.path.exists(PENDING_FILE):
            os.remove(PENDING_FILE)
            print("\n🗑️ 작업 완료. 대기 파일이 삭제되었습니다.")
            
    else:
        print("\n🚫 작업을 취소했습니다. 디스코드에 취소 알림을 전송합니다.")
        send_discord_cancel(target_name, command)
        
        if os.path.exists(PENDING_FILE):
            os.remove(PENDING_FILE)
            print("🗑️ 대기 파일이 폐기되었습니다.")

if __name__ == "__main__":
    main()
