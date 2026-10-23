# 🛡️ 일일 보안 취약점 & 위협 인텔리전스 브리핑 (2026년 10월 23일)
> **보안업계 취준생 & 엔지니어를 위한 고위험 취약점(CVSS High/Critical) 및 주요 보안 뉴스 데일리 요약**

## 📊 오늘 탐지된 핵심 지표
- **🔴 Critical (9.0 ~ 10.0):** 8건
- **🟠 High (7.0 ~ 8.9):** 47건
- **⚠️ CISA KEV (실제 침해사고 악용 확인):** 0건
- **📰 연동 보안 뉴스 기사:** 30건

## 🚨 NVD 공식 등재 고위험 취약점 분석 (CVSS ≥ 7.0)
### 1. 🔴 CRITICAL `CVE-2026-102785` (CVSS 10.0)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-434`
- **취약점 설명:** Joomla Extension - yootheme.com - Unauthenticated remote code execution in YOOtheme Pro 5.0.0-5.0.52 - YOOtheme Pro’s publicly accessible image transformation handler incompletely binds normalized image operations and the output destination to its request signature. An unauthenticated remote attacker can reuse a signature disclosed in a legitimate public image URL, inject additional image operations, traverse out of the intended cache directory, and write an attacker-controlled PNG/PHP polyglot to an executable public media directory.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 원격에서 셸 획득이 가능하므로 즉각적인 PoC 분석 및 방화벽/WAF 차단 룰셋 배포 우선순위 최고.
  - 🛡️ **방어 관점:** 최신 벤더 공식 보안 패치 권고 및 불필요한 포트/외부 노출 서비스 폐쇄 확인 필요.
- **상세 링크:** [참고자료](https://www.yootheme.com/)

### 2. 🔴 CRITICAL `CVE-2021-48014` (CVSS 9.8)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-22` - 경로 조작/디렉터리 탐색 (Path Traversal) - 중요 시스템 파일(/etc/passwd 등) 열람 및 권한 탈취
- **취약점 설명:** FineReport 9.0 contains a path traversal vulnerability in the /WebReport/ReportServer design_save_svg operation that allows unauthenticated attackers to write arbitrary files via the filePath parameter. Attackers can send a POST request with directory traversal sequences in filePath and a __CONTENT__ payload to write a JSP webshell and achieve remote code execution. Exploitation evidence was first observed by the Shadowserver Foundation on 2023-10-14.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 원격에서 셸 획득이 가능하므로 즉각적인 PoC 분석 및 방화벽/WAF 차단 룰셋 배포 우선순위 최고.
  - 🛡️ **방어 관점:** 최신 벤더 공식 보안 패치 권고 및 불필요한 포트/외부 노출 서비스 폐쇄 확인 필요.
- **상세 링크:** [참고자료](https://github.com/NHPT/WebReportV9Exp/blob/main/WebReport_Exp.py) | [참고자료](https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E5%B8%86%E8%BD%AFOA/%E5%B8%86%E8%BD%AF%E6%8A%A5%E8%A1%A8%20V9%20design_save_svg%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%A6%86%E7%9B%96%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0.md)

### 3. 🔴 CRITICAL `CVE-2021-48016` (CVSS 9.8)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-94` - 코드 인젝션 (Code Injection) - 서버 측 임의 명령/코드 실행
- **취약점 설명:** DedeCMS through 5.8.1-beta contains a PHP code injection vulnerability in ShowMsg() where the HTTP Referer header is written into a DedeTemplate string and included. Unauthenticated attackers can send a crafted Referer to /plus/flink.php?dopost=save with an empty validate code to execute arbitrary PHP and system commands. Exploitation evidence was first observed by the Shadowserver Foundation on 2023-10-14.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/dedecms/DedeCMS/blob/v5.8.1/include/common.func.php) | [참고자료](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dedecms/dedecms-rce.yaml)

### 4. 🔴 CRITICAL `CVE-2026-112832` (CVSS 9.8)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-98`
- **취약점 설명:** Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in CozyThemes Rootblox rootblox allows PHP Local File Inclusion.This issue affects Rootblox: from n/a through 1.0.6.
- **💡 취준생 실무/면접 체크포인트:**
  - 🛡️ **방어 관점:** CVSS Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`를 기반으로 사내 자산 인벤토리 취약 버전 식별 및 긴급 보안 권고문 발행 대상.
- **상세 링크:** [참고자료](https://patchstack.com/database/wordpress/plugin/rootblox/vulnerability/wordpress-rootblox-plugin-1-0-6-local-file-inclusion-vulnerability?_s_id=cve)

### 5. 🔴 CRITICAL `CVE-2026-97631` (CVSS 9.5)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-120`
- **취약점 설명:** EDK2 contains a vulnerability in BIOS where a user may cause “Out-of-bounds
Write”, Classic
Buffer Overflow, and “Incorrect Calculation of Buffer Size” by remote access. Successful exploitation of this vulnerability
can lead to arbitrary
code execution. It could also impact
Confidentiality,
Integrity,
and Availability.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 원격에서 셸 획득이 가능하므로 즉각적인 PoC 분석 및 방화벽/WAF 차단 룰셋 배포 우선순위 최고.
  - 🛡️ **방어 관점:** 최신 벤더 공식 보안 패치 권고 및 불필요한 포트/외부 노출 서비스 폐쇄 확인 필요.
- **상세 링크:** [참고자료](https://github.com/tianocore/edk2/security/advisories/GHSA-99cj-7hg9-mp4m)

### 6. 🔴 CRITICAL `CVE-2026-111497` (CVSS 9.2)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-252`
- **취약점 설명:** A buffer overflow vulnerability in the Brotli decoder (c/dec/decode.c) in Google Brotli versions 1.0.3 through 1.2.0 on all platforms allows a remote unauthenticated attacker to corrupt adjacent decoder state memory, disclose sensitive memory contents, cause a denial of service, or potentially execute arbitrary code using a crafted Brotli-compressed stream.





Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
  - 📰 **관련 보도:**
    - [The Hacker News] [Researchers Demonstrate Node2Shell RCE Exploit on Node.js Build Using Crafted Brotli Data](https://thehackernews.com/2026/10/researchers-demonstrate-node2shell-rce.html)
- **상세 링크:** [참고자료](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#nodejs-brotli-decoder-out-of-bounds-write-permits-remote-code-execution-cve-2026-111497---high)

### 7. 🔴 CRITICAL `CVE-2022-51022` (CVSS 9.1)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-22` - 경로 조작/디렉터리 탐색 (Path Traversal) - 중요 시스템 파일(/etc/passwd 등) 열람 및 권한 탈취
- **취약점 설명:** YiShaAdmin 2.2 through 3.1, fixed in commit 025b062, contains an unauthenticated path traversal vulnerability in the /admin/File/DownloadFile endpoint that allows attackers to read and delete arbitrary files via the filePath parameter. Attackers can send crafted GET requests with directory traversal sequences in filePath and set the delete parameter to read or remove system files like etc/passwd. Exploitation evidence was first observed by the Shadowserver Foundation on 2023-10-20.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/liukuo362573/YiShaAdmin/commit/025b0628b1295bd2d9fd6c9b5b82692a345151ef) | [참고자료](https://github.com/liukuo362573/YiShaAdmin/commit/c3b66e66bf6d70a561190cd8da7f4df7b141931d)

### 8. 🔴 CRITICAL `CVE-2026-114607` (CVSS 9.1)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-287` - 부적절한 인증 (Improper Authentication) - 인증 우회 후 관리자 권한 획득
- **취약점 설명:** Better Auth is an authentication and authorization library for TypeScript. From 1.4.0-beta.18 until 1.7.7, deployments that enable Magic Link with storeToken set to plain, or with storeToken set to hashed and the global verification.storeIdentifier setting also set to hashed, enable a built-in social or Generic OAuth provider, and use account.storeStateStrategy set to database can accept an OAuth sign-in state value as a Magic Link token. These settings can cause Magic Link verification records and OAuth state to resolve to the same stored identifier, allowing an unauthenticated attacker to start OAuth sign-in for a known email address and redeem the returned state through Magic Link without controlling the mailbox or completing the provider callback. The attacker can obtain a normal session for an existing user, or create an account incorrectly marked as email verified when sign-up is enabled. This issue is fixed in version 1.7.7.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/better-auth/better-auth/commit/ac54bfd67821a7607533af2059858b12bc54e26a) | [참고자료](https://github.com/better-auth/better-auth/pull/11494)

### 9. 🟠 HIGH `CVE-2026-115328` (CVSS 8.8)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔑 **일반 사용자 권한 필요** | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-89` - SQL 인젝션 (SQL Injection) - 데이터베이스 무단 열람, 변조 및 인증 우회
- **취약점 설명:** JSON-SCADA before 0.65-alpha contains an sql injection vulnerability in opcApi() in src/server_realtime_auth/index.js that allows authenticated users to inject SQL via HistoryReadRequest parameters. Attackers can inject stacked statements through NodeId.Id, StartTime, or EndTime values to read, modify, or delete historian data across all locations regardless of role.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/riclolsen/json-scada) | [참고자료](https://github.com/riclolsen/json-scada/blob/V0.64-alpha/src/server_realtime_auth/index.js#L2175-L2224)

### 10. 🟠 HIGH `CVE-2026-115330` (CVSS 8.8)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔑 **일반 사용자 권한 필요** | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-89` - SQL 인젝션 (SQL Injection) - 데이터베이스 무단 열람, 변조 및 인증 우회
- **취약점 설명:** Lotus through 0.10.2 contains an sql injection vulnerability that allows authenticated organization users to execute arbitrary SQL by appending stacked statements to custom metric queries. Attackers can submit semicolon-separated SQL through POST /app/metrics/, bypassing first-statement-only validation, to read or modify data across all tenants.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/uselotus/lotus) | [참고자료](https://github.com/uselotus/lotus/blob/0.10.2/backend/metering_billing/aggregation/billable_metrics.py#L643-L656)

## 📰 주요 보안 뉴스 & 제로데이 동향
- **[The Hacker News]** [Critical Flaw in Python’s Popular Pillow Image Library Allows Code Execution via a Crafted Image](https://thehackernews.com/2026/10/critical-flaw-in-pythons-popular-pillow.html) (`CVE-2026-112900`)
  > Pillow, the most widely used image library for Python, can be made to run operating system commands on a server by specifying the name of a file it is...
- **[The Hacker News]** [Researchers Demonstrate Node2Shell RCE Exploit on Node.js Build Using Crafted Brotli Data](https://thehackernews.com/2026/10/researchers-demonstrate-node2shell-rce.html) (`#RCE` `#PoC Released` `CVE-2026-111497`)
  > Malicious Brotli data can make an application on an official build of Node.js run attacker-supplied code, security researchers at Imperva have&nbsp;de...
- **[The Hacker News]** [Critical x402 SDK Flaw Could Let Malicious APIs Drain AI Agents’ Token Balances](https://thehackernews.com/2026/10/critical-x402-sdk-flaw-could-let.html)
  > AI agents paying for API calls with the&nbsp;x402 SDKs&nbsp;could sign a payment for their full balance of a supported token if a malicious API asked ...
- **[The Hacker News]** [PHP2Shell Exploit Attempts Hit Millions as Attackers Try to Deploy Mirai Malware](https://thehackernews.com/2026/10/php2shell-exploit-attempts-hit-millions.html) (`CVE-2026-109618` `CVE-2026-109619`)
  > Threat actors have been observed unsuccessfully attempting to exploit the newly disclosed PHP2Shell vulnerabilities to rope infected systems into a Mi...
- **[The Hacker News]** [The AI Agent Nobody Owns: Watch Expert Webinar On Your Newest Insider Threat](https://thehackernews.com/2026/10/the-ai-agent-nobody-owns-watch-expert.html)
  > Right now, there is probably an AI agent running on a laptop somewhere in your network. It stores API keys and database passwords, can access your int...
- **[The Hacker News]** [Arista Warns of Critical VeloCloud SQL Injection Zero-Day Exploited in Attacks](https://thehackernews.com/2026/10/arista-warns-of-critical-velocloud-sql.html) (`#Zero-Day`)
  > Attackers are exploiting a zero-day SQL injection flaw in Arista's VeloCloud Orchestrator (VCO), the&nbsp;central management system&nbsp;for VeloCloud...
- **[The Hacker News]** [eMudhra to Exit Global SSL/TLS Business After 8 Intermediate CA Keys Found Easily Guessable](https://thehackernews.com/2026/10/emudhra-to-exit-global-ssltls-business.html)
  > eMudhra, an Indian certificate authority (CA), will withdraw from its global SSL/TLS certificate business,&nbsp;its board decided on Thursday. The dec...
- **[The Hacker News]** [ThreatsDay: AI Secrets Leak, PingCAP Source Theft, Signal Hang-Up Flaw, Laravel Auth Bypass + 21 More](https://thehackernews.com/2026/10/threatsday-ai-secrets-leak-pingcap.html) (`#RCE`)
  > This week has already been rough for cybersecurity. Critical PHP and GitLab RCE flaws, serious Linux security bugs, compromised eMudhra certificates, ...

## 🎓 취준생을 위한 데일리 스터디 가이드
1. **보안관제 지원자:** 오늘의 Critical 취약점 포트 및 프로토콜을 확인하고, Snort/Suricata 탐지 시그니처 작성 아이디어 구상해보기.
2. **취약점 진단/모의해킹 지원자:** CWE 유형별 취약한 코드 패턴(취약한 함수 호출, 검증 부재 등)을 파악하고 재현 시나리오(PoC) 흐름 이해하기.
3. **보안기획/컨설팅 지원자:** CISA KEV 등재 건을 중심으로 패치 우선순위 산정 및 사내 취약점 조치 프로세스(ISMS-P 인증항목 2.10.1 취약점 점검 및 조치) 연결짓기.