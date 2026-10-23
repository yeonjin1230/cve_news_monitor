# 🛡️ 일일 보안 취약점 & 위협 인텔리전스 브리핑 (2026년 10월 23일)
> **보안업계 취준생 & 엔지니어를 위한 고위험 취약점(CVSS High/Critical) 및 주요 보안 뉴스 데일리 요약**

## 📊 오늘 탐지된 핵심 지표
- **🔴 Critical (9.0 ~ 10.0):** 3건
- **🟠 High (7.0 ~ 8.9):** 16건
- **⚠️ CISA KEV (실제 침해사고 악용 확인):** 0건
- **📰 연동 보안 뉴스 기사:** 2건

## 🚨 NVD 공식 등재 고위험 취약점 분석 (CVSS ≥ 7.0)
### 1. 🔴 CRITICAL `CVE-2026-114612` (CVSS 9.9)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔑 **일반 사용자 권한 필요** | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행) | 💥 **영향 범위 확장** (컨테이너/VM 탈출 등 다른 영역 침해 가능)
- **취약점 유형(CWE):** `CWE-269`
- **취약점 설명:** LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From 1.87.0 until 1.100.4, 1.101.3, 1.102.2, 1.103.1, and 1.104.0-rc.2, the proxy reuses one cryptographic context for at-rest secrets and session tokens, allowing an authenticated internal user to have crafted metadata containing a forged administrator credential encrypted and returned by the API-key flow. Replaying that ciphertext as a bearer token causes the proxy to trust the forged proxy administrator identity, permitting administrative access and arbitrary commands through the MCP stdio endpoint. Versions 1.87.0 through 1.90.x require EXPERIMENTAL_UI_LOGIN to be enabled, while versions after 1.91.0 are exploitable in the default configuration. This issue was fixed in LiteLLM 1.100.4, 1.101.3, 1.102.2, 1.103.1, and 1.104.0-rc.2.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/BerriAI/litellm/commit/1d5fdc87fed66b49e1df8cf7d708ad93249eb7d0) | [참고자료](https://github.com/BerriAI/litellm/commit/9161d7f9d6073603ba61ee4aa5e2c0ef5b37a81b)

### 2. 🔴 CRITICAL `CVE-2022-51026` (CVSS 9.8)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-290`
- **취약점 설명:** Bytebase 0.12.0 before 1.0.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to log in as any user. The flaw stems from trusting client-supplied GitLab provider configuration in the POST /api/auth/login/GITLAB_SELF_HOST endpoint. Attackers can set instanceUrl to a server they control that returns an active user with a chosen email. Bytebase then issues session tokens for that principal, letting attackers impersonate existing users including the Owner or create new members.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/bytebase/bytebase) | [참고자료](https://github.com/bytebase/bytebase/blob/1.0.0/server/auth.go#L79-L93)

### 3. 🔴 CRITICAL `CVE-2026-114611` (CVSS 9.1)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-295`
- **취약점 설명:** OCO-Server is a self-hosted endpoint management application for computer inventory, software deployment, and mobile device management. Prior to 1.2.3,the Apple MDM enrollment endpoint `frontend/api-mdm.php` verifies the signed enrollment-request plist with `openssl_pkcs7_verify(..., PKCS7_NOVERIFY, ...)`. `PKCS7_NOVERIFY` disables signer certificate chain and trust validation, so the signature only has to be self-consistent with whatever certificate is embedded in the PKCS#7 blob. A self-signed certificate from an unrelated attacker is accepted. Because the endpoint trusts the `SERIAL` field taken from the unverified payload, anyone who knows a registered device's serial number can sign a forged plist (`SERIAL` = victim device, attacker-chosen `UDID`) with an arbitrary self-signed certificate; POST it unauthenticated to `/api-mdm.php/profile` (Content-Type: `application/pkcs7-signature`); and receive the victim device's freshly minted MDM identity: a certificate with `CN=<serial>` issued by the server's internal MDM device CA, bundled with its private key in a PKCS#12 payload inside the returned `.mobileconfig` enrollment profile. Additionally, the victim's `mobile_device` database row is silently overwritten with the attacker-supplied `UDID` (device-record hijack). With the stolen certificate and key, the attacker can impersonate the victim device on all subsequent MDM traffic (`/checkin`, `/mdm`, `/parameters`), which authenticate callers by the certificate CN (the serial number) via `checkSignature()` in the same file. This yields control over the victim device's MDM relationship: reading its management data, replacing its push token, and disrupting or redirecting its enrollment. Version 1.2.3 fixes the issue.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/schorschii/OCO-Server/commit/5cab5ad2461434816d706b7be9cc08bda15c1404) | [참고자료](https://github.com/schorschii/OCO-Server/commit/f3a6591136f9bd92aff39ddfb26587e6dfdb64df)

### 4. 🟠 HIGH `CVE-2026-108358` (CVSS 8.8)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-611`
- **취약점 설명:** PhpSpreadsheet is a pure PHP library for reading and writing spreadsheet files. Prior to 1.30.7, 2.1.19, 2.4.8, 3.10.8, and 5.10.0, XmlScanner::scan in src/PhpSpreadsheet/Reader/Security/XmlScanner.php uses a DOCTYPE detection pattern that accounts for NUL-byte interleaving but not ISO-2022 escape sequences in XLSX XML parts. The escape sequences prevent the scanner from matching the declaration, and XML charset normalization then removes the escape bytes before parsing, exposing a valid DOCTYPE and entity definitions. Processing an attacker-controlled XLSX can therefore cause entity-expansion denial of service on supported PHP versions and can permit local file access or SSRF on PHP before 8.0 or when LIBXML_NOENT is enabled. This issue is fixed in versions 1.30.7, 2.1.19, 2.4.8, 3.10.8, and 5.10.0.
- **💡 취준생 실무/면접 체크포인트:**
  - 🛡️ **방어 관점:** CVSS Vector `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:L/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X`를 기반으로 사내 자산 인벤토리 취약 버전 식별 및 긴급 보안 권고문 발행 대상.
- **상세 링크:** [참고자료](https://github.com/PHPOffice/PhpSpreadsheet/commit/299993894dce37aa3b64aa23e9a3f4bb77ab0e66) | [참고자료](https://github.com/PHPOffice/PhpSpreadsheet/commit/89f455c133e1a7e2d4abfadc43ce29eb7450d781)

### 5. 🟠 HIGH `CVE-2026-108359` (CVSS 8.7)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-400`
- **취약점 설명:** PhpSpreadsheet is a pure PHP library for reading and writing spreadsheet files. Prior to 1.30.7, 2.1.19, 2.4.8, 3.10.8, and 5.10.0, Ods::processTableRow in src/PhpSpreadsheet/Reader/Ods.php accepts an unbounded table:number-rows-repeated attribute from an ODS table row. When the row contains a value, the reader materializes a cell for every repetition without checking the spreadsheet row limit, so a small attacker-controlled ODS file can consume substantial CPU and memory and terminate the PHP worker. Column repetition is separately bounded and is not part of this vulnerability. This issue is fixed in versions 1.30.7, 2.1.19, 2.4.8, 3.10.8, and 5.10.0.
- **💡 취준생 실무/면접 체크포인트:**
  - 🛡️ **방어 관점:** CVSS Vector `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X`를 기반으로 사내 자산 인벤토리 취약 버전 식별 및 긴급 보안 권고문 발행 대상.
- **상세 링크:** [참고자료](https://github.com/PHPOffice/PhpSpreadsheet/commit/299993894dce37aa3b64aa23e9a3f4bb77ab0e66) | [참고자료](https://github.com/PHPOffice/PhpSpreadsheet/commit/2de29384aa11223ee08136c0e6a9e9981bc1a2eb)

### 6. 🟠 HIGH `CVE-2026-114519` (CVSS 8.6)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔑 **일반 사용자 권한 필요** | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-862` - 인가 누락 (Missing Authorization) - 수평/수직 권한 상승을 통한 비인가 자원 접근
- **취약점 설명:** Missing Authorization (CWE-862) in the user API of Roskus Prospero Flow CRM from 2.0.0 before 5.26.0 allows a user with a basic role to read the accounts of other users of its own company, including accounts with higher privileges, and, in versions from 3.5.0, to delete them, because the routes GET /api/user/{id} and DELETE /api/user/{id} in routes/api.php carry only the auth:api middleware, which checks that a JSON Web Token is valid and nothing more, and neither UserReadController::read() nor UserDeleteController::delete() checks a permission, a policy or a role before acting. Object access is scoped by company: the read path limits the query to the company of the authenticated user, and the delete path compares the company of the target account with the company of the authenticated user. The delete path skips that comparison when the company of the authenticated user is Company::DEFAULT_COMPANY, so a user with a basic role in that company can delete any account of any company of the installation. Deleting an account removes the data held on it, and the last administrative account of a company can be deleted. This gives the attacker the personal data held on the other accounts, including email address, telephone number, postal address and IBAN, and the ability to delete accounts it has no permission to administer.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/Roskus/prospero-flow-crm/commit/52cd172ccc7c3332805d9e0b7fc992bda3d422bf) | [참고자료](https://secur0.com/en/cna/cve-list/cve-2026-114519-missing-authorization-user-api)

### 7. 🟠 HIGH `CVE-2026-115353` (CVSS 8.6)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행) | 💥 **영향 범위 확장** (컨테이너/VM 탈출 등 다른 영역 침해 가능)
- **취약점 유형(CWE):** `CWE-22` - 경로 조작/디렉터리 탐색 (Path Traversal) - 중요 시스템 파일(/etc/passwd 등) 열람 및 권한 탈취
- **취약점 설명:** Mistune before 3.3.0 contains a path traversal vulnerability in the RST include directive that allows attackers to read arbitrary files by supplying relative or absolute paths. Attackers can submit markdown containing include directives referencing ../ sequences or absolute paths to embed sensitive files like credentials or environment data in rendered HTML.
- **💡 취준생 실무/면접 체크포인트:**
  - 🛡️ **방어 관점:** CVSS Vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`를 기반으로 사내 자산 인벤토리 취약 버전 식별 및 긴급 보안 권고문 발행 대상.
- **상세 링크:** [참고자료](https://github.com/lepture/mistune/security/advisories/GHSA-9jjx-3hq3-hx4j) | [참고자료](https://www.vulncheck.com/advisories/mistune-before-3.3.0-path-traversal-via-include-directive)

### 8. 🟠 HIGH `CVE-2026-113874` (CVSS 8.1)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔑 **일반 사용자 권한 필요** | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)
- **취약점 유형(CWE):** `CWE-863`
- **취약점 설명:** SmileCDR HAPI FHIR allows an untrusted bundle body to replace a partition identity previously established by a trusted source, and does not enforce storage partition entitlement by default. An attacker authorized for one tenant can read from or write to another tenant's partition.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-294-01.json) | [참고자료](https://www.cve.org/CVERecord?id=CVE-2026-113874)

### 9. 🟠 HIGH `CVE-2026-97635` (CVSS 8.1)
- **공격 벡터 해석:** 🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투) | 🔓 **인증 불필요** (로그인 없이 무인가 공격 가능) | 🖱️ **사용자 유도 필요** (피싱 링크/파일 실행 필요)
- **취약점 유형(CWE):** `CWE-79` - XSS (Cross-site Scripting) - 사용자 세션 탈취, 악성 스크립트 실행
- **취약점 설명:** The Agent Zero Web UI before 1.15 does not correctly sanitize user-provided input in chat messages or file uploads. When Agent Zero reproduces content in the chat interface, any injected JavaScript is executed in the context of the victim’s authenticated Agent Zero Web UI session.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://github.com/agent0ai/agent-zero/issues/943) | [참고자료](https://github.com/agent0ai/agent-zero/releases/tag/v1.15)

### 10. 🟠 HIGH `CVE-2026-13599` (CVSS 7.8)
- **공격 벡터 해석:** 💻 **로컬 접근 필요** (시스템 내부 계정 필요) | 🔑 **일반 사용자 권한 필요** | ⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행) | 💥 **영향 범위 확장** (컨테이너/VM 탈출 등 다른 영역 침해 가능)
- **취약점 유형(CWE):** `CWE-306`
- **취약점 설명:** Missing authentication for critical function vulnerability in ABB Ability Edgenius.

This issue affects Ability Edgenius: through 3.2.3.0.
- **💡 취준생 실무/면접 체크포인트:**
  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.
  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.
- **상세 링크:** [참고자료](https://search.abb.com/library/Download.aspx?DocumentID=7PAA026271&LanguageCode=en&DocumentPartId=&Action=Launch)

## 📰 주요 보안 뉴스 & 제로데이 동향
- **[The Hacker News]** [URGENT - PHP Warns of Another Unpatched RCE Two Days After Emergency PHP2Shell Patches](https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html) (`#RCE` `CVE-2026-115560`)
  > PHP has warned of another way an attacker could run code on a web server, two days after it shipped emergency fixes for the critical PHP2Shell flaws. ...
- **[The Hacker News]** [Russian-Linked Hackers Used New Mesh Network Backdoor in Destructive Ukraine Attack](https://thehackernews.com/2026/10/russian-linked-hackers-used-new-mesh.html)
  > The Russian state-sponsored hacking group Sandworm teamed up with another threat actor to carry out a destructive wiping attack targeting a Ukrainian ...

## 🎓 취준생을 위한 데일리 스터디 가이드
1. **보안관제 지원자:** 오늘의 Critical 취약점 포트 및 프로토콜을 확인하고, Snort/Suricata 탐지 시그니처 작성 아이디어 구상해보기.
2. **취약점 진단/모의해킹 지원자:** CWE 유형별 취약한 코드 패턴(취약한 함수 호출, 검증 부재 등)을 파악하고 재현 시나리오(PoC) 흐름 이해하기.
3. **보안기획/컨설팅 지원자:** CISA KEV 등재 건을 중심으로 패치 우선순위 산정 및 사내 취약점 조치 프로세스(ISMS-P 인증항목 2.10.1 취약점 점검 및 조치) 연결짓기.