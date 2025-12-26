#!/bin/bash

# 1. 스플렁크가 강제로 설정한 환경변수 해제 (중요!)
unset PYTHONPATH
unset LD_LIBRARY_PATH

# 2. 우리가 라이브러리 설치해둔 시스템 파이썬으로 실행
# "$@"는 스플렁크가 던져준 로그 파일 경로 등 인자값을 그대로 넘긴다는 뜻
/usr/bin/python3 /opt/splunk/bin/scripts/ai_advisor.py "$@"
