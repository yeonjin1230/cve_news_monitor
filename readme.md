# 🛡️ CVE & Security Threat Daily Monitor

> **보안업계 취업준비생 및 보안 엔지니어를 위한 NVD 공식 고위험 취약점 & 글로벌/국내 보안 뉴스 자동 수집·분석·알림 시스템**

매일 수천 건씩 쏟아지는 취약점 데이터 중에서 실무와 면접에서 반드시 알아야 하는 고위험 취약점(CVSS ≥ 7.0, CISA KEV 실공격 악용 건)과 **주요 보안 언론사의 최신 뉴스/제로데이 동향**을 자동으로 크롤링·교차 분석하여 메신저(Discord, Telegram, Slack)로 전달해 주는 완전 자동화 시스템입니다.

## 🌟 주요 특징

1. **NIST NVD API v2.0 공식 연동**

   * 미국 국립표준기술연구원(NIST) NVD 2.0 API를 통해 공식 등재된 취약점 수집

   * CVSS v3.1 / v4.0 위험도 필터링: **High(7.0 \~ 8.9)** 및 **Critical(9.0 \~ 10.0)** 우선 선별

2. **CISA KEV (Known Exploited Vulnerabilities) 교차 검증**

   * 미국 CISA가 발표하는 '실제 야생에서 해커들이 활발히 악용 중인 취약점 목록'과 대조하여 긴급 대응 대상 식별

3. **글로벌 & 국내 주요 보안 언론사 RSS 실시간 연동**

   * **The Hacker News (THN)**: 글로벌 최신 해킹 트렌드 및 제로데이

   * **BleepingComputer**: 랜섬웨어, PoC 익스플로잇 공개 동향

   * **SecurityWeek**: 글로벌 엔터프라이즈 보안 분석

   * **보안뉴스 (BoanNews)**: 국내 최대 정보보안 전문 미디어

   * **KrCERT/CC (KISA)**: 한국인터넷진흥원 긴급 보안공지

4. **취준생 맞춤형 인텔리전스 분석**

   * **CVSS 공격 벡터 쉬운 한국어 해설**: 네트워크 원격 침투 가능 여부(`AV:N`), 인증 불필요 여부(`PR:N`), 사용자 개입 여부(`UI:N`) 자동 분석

   * **CWE 매핑**: 취약점 근본 원인(버퍼 오버플로우, SQL 인젝션, 역직렬화, 인증 우회 등) 설명

   * **보안 직무별 면접/스터디 포인트 제공**: 보안관제(탐지 룰셋), 취약점 진단/모의해킹(익스플로잇 흐름), 보안기획(패치 관리 및 ISMS-P)

5. **멀티 메신저 자동 알림 지원**

   * Discord Webhook, Telegram Bot, Slack Webhook, Markdown 일일 보고서 파일 자동 생성

6. **서버 비용 0원 (GitHub Actions 완전 무료 지원)**

   * 24시간 켜둘 서버 없이도 GitHub Actions 크론 스케줄러로 매일 정해진 시간에 자동 실행 가능

## 📂 프로젝트 구조

```
├── cve_news_monitor.py      # 메인 파이프라인 스크립트 (NVD 수집, RSS 크롤러, 분석, 알림)
├── cve_monitor_state.json   # 수집한 CVE/뉴스 URL 중복 방지 상태 저장소 (자동 생성)
├── daily_security_briefing.md # 생성된 마크다운 보고서
└── README.md                # 사용 가이드 및 배포 설명서

```

## 🚀 빠른 시작 (Local 실행)

별도의 외부 무거운 패키지 설치 없이 **Python 3.8+ 표준 라이브러리**만으로 즉시 구동됩니다.

### 1. 테스트 모드 실행 (샘플 데이터 및 서식 검증)

인터넷 연결 여부와 무관하게 시스템 동작과 보고서 양식을 즉시 확인해볼 수 있습니다.

```
python3 cve_news_monitor.py --test --output test_briefing.md

```

### 2. 실제 실시간 데이터 수집 실행

최근 1일간 등재된 CVSS 7.0 이상 취약점과 보안 뉴스를 수집합니다.

```
python3 cve_news_monitor.py --days 1 --cvss-min 7.0 --output daily_briefing.md

```

### 3. 주요 CLI 옵션 안내

| 옵션 | 기본값 | 설명 | 
| ----- | ----- | ----- | 
| `--days` | `1` | 과거 몇 일간의 취약점을 수집할지 지정 (1\~7일 권장) | 
| `--cvss-min` | `7.0` | 최소 CVSS 점수 필터 (7.0 = High 이상, 9.0 = Critical만) | 
| `--output`, `-o` | `daily_security_briefing.md` | 저장할 마크다운 보고서 경로 | 
| `--test` | `False` | 시뮬레이션용 최신 위협 목 데이터로 테스트 실행 | 
| `--dry-run` | `False` | 중복 방지 DB에 기록하지 않고 1회성 출력 | 
| `--discord` | `None` | 디스코드 웹훅 URL | 
| `--slack` | `None` | 슬랙 웹훅 URL | 
| `--telegram-token` | `None` | 텔레그램 봇 API 토큰 | 
| `--telegram-chat-id` | `None` | 텔레그램 수신 채팅방 ID | 

## 🔔 알림 채널 연동 방법

### 1. Discord (디스코드) 연동 (가장 추천: 1분 소요)

1. 알림을 받을 디스코드 서버의 채널 설정(`⚙️`) 클릭

2. **연동(Integrations) > 웹후크(Webhooks) > 새 웹후크 만들기** 클릭

3. 생성된 웹후크 URL 복사 후 아래와 같이 실행:

```
python3 cve_news_monitor.py --discord "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"

```

### 2. Telegram (텔레그램) 연동

1. 텔레그램에서 `@BotFather` 검색 후 `/newbot` 명령어로 봇 생성 → **API Token** 획득

2. 생성한 봇에게 아무 메시지나 전송

3. 브라우저에서 `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` 접속하여 `chat.id` 확인

4. 실행 명령어:

```
python3 cve_news_monitor.py --telegram-token "YOUR_BOT_TOKEN" --telegram-chat-id "YOUR_CHAT_ID"

```

### 3. Slack (슬랙) 연동

1. [Slack API Apps](https://api.slack.com/apps)에서 앱 생성 후 **Incoming Webhooks** 활성화

2. 채널에 웹훅 추가 후 Webhook URL 획득

3. 실행 명령어:

```
python3 cve_news_monitor.py --slack "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

```

## ⏰ 완전 무료 24/7 자동화 (GitHub Actions 배포)

개인 PC를 켜두거나 유료 클라우드 서버(AWS, GCP)를 결제할 필요가 없습니다. GitHub 무료 워크플로우를 사용하면 매일 아침 자동으로 실행되어 핸드폰 메신저로 브리핑이 날아옵니다.

### 설정 순서:

1. 본인의 GitHub에 새 비공개(Private) 또는 공개(Public) 리포지토리를 생성합니다.

2. `cve_news_monitor.py` 파일을 업로드합니다.

3. 리포지토리의 **Settings > Secrets and variables > Actions**에서 새 시크릿을 등록합니다:

   * `DISCORD_WEBHOOK_URL`: 본인의 디스코드 웹훅 주소

   * `NVD_API_KEY`: (선택) [NVD 공식 사이트](https://nvd.nist.gov/developers/request-an-api-key)에서 무료 발급받은 API 키

4. `.github/workflows/cve_daily_alert.yml` 파일을 만들고 아래 코드를 저장합니다:

```
name: Daily Security CVE & News Alert

on:
  schedule:
    # 매일 한국 시간 기준 오전 8시 (UTC 23:00) 자동 실행
    - cron: '0 23 * * *'
  workflow_dispatch: # 수동 즉시 실행 지원

jobs:
  run-monitor:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run CVE & News Monitor
        env:
          DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: |
          python cve_news_monitor.py --days 1 --cvss-min 7.0 --output security_briefing.md

      - name: Commit Updated State (Deduplication)
        run: |
          git config --global user.name "github-actions[bot]"
          git config --global user.email "github-actions[bot]@users.noreply.github.com"
          git add cve_monitor_state.json security_briefing.md || true
          git commit -m "Auto-update vulnerability briefing & state [skip ci]" || true
          git push || true

```

## 💡 보안 취준생을 위한 활용 꿀팁 (포트폴리오 & 면접)

1. **깃허브 포트폴리오 활용**: 본 시스템을 직접 배포한 리포지토리를 이력서(Notion/PDF)에 기재하여 "보안 위협 인텔리전스(TI) 자동화 수집 파이프라인 구축 경험"으로 어필할 수 있습니다.

2. **면접 전날 5분 브리핑 확인**: 면접관이 자주 묻는 "최근에 가장 인상 깊게 본 보안 취약점이나 보안 이슈가 있나요?" 질문에 당일 아침 생성된 CISA KEV 및 Critical CVE 브리핑 내용으로 구체적인 기술 답변이 가능합니다.

3. **CWE와 CVSS 벡터 연계 학습**: 단순히 CVE 번호만 외우는 것이 아니라, 공격 벡터(`AV:N`, `PR:N`)와 취약 원인(CWE-94, CWE-787 등), 완화 방안을 세트로 정리하는 습관을 기를 수 있습니다.