#!/usr/bin/env python3
"""
CVE & Security News Automation Monitor
=======================================
보안업계 취업준비생 및 보안 엔지니어를 위한 취약점 자동 수집·분석·알림 시스템

주요 기능:
1. NIST NVD API v2.0 연동 (CVSS v3.1 / v4.0 High & Critical 필터링)
2. CISA KEV (Known Exploited Vulnerabilities, 실제 공격 악용 취약점) 교차 검증
3. 주요 글로벌/국내 보안 뉴스 RSS 수집 (The Hacker News, BleepingComputer, SecurityWeek, 보안뉴스)
4. CVE와 뉴스 간 상호 연관성 분석 및 키워드 태깅 (RCE, Zero-Day, PoC 등)
5. 보안 취준생 맞춤형 분석 요약 (공격 벡터 해석, CWE 원인 분석, 모의해킹/보안관제 대응 방안)
6. 멀티 채널 알림 발송 (Discord, Slack, Telegram, 콘솔, 마크다운 보고서 저장)
7. JSON 기반 중복 알림 방지 상태 관리 (모든 OS 및 GitHub Actions 환경 호환)
"""

import os
import sys
import json
import argparse
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("CVEMonitor")


# =====================================================================
# 데이터 모델 정의
# =====================================================================

@dataclass
class CVSSInfo:
    version: str = "3.1"
    base_score: float = 0.0
    severity: str = "UNKNOWN"
    vector_string: str = ""
    attack_vector: str = "UNKNOWN"  # Network, Adjacent, Local, Physical
    privileges_required: str = "UNKNOWN"  # None, Low, High
    user_interaction: str = "UNKNOWN"  # None, Required
    scope: str = "UNKNOWN"  # Unchanged, Changed

    def explain_vector_kr(self) -> str:
        """취준생을 위한 CVSS 벡터 쉬운 한국어 설명"""
        explanations = []
        if self.attack_vector == "NETWORK":
            explanations.append("🌐 **원격 네트워크 공격 가능** (인터넷을 통한 원격 침투)")
        elif self.attack_vector == "LOCAL":
            explanations.append("💻 **로컬 접근 필요** (시스템 내부 계정 필요)")
        
        if self.privileges_required == "NONE":
            explanations.append("🔓 **인증 불필요** (로그인 없이 무인가 공격 가능)")
        elif self.privileges_required == "LOW":
            explanations.append("🔑 **일반 사용자 권한 필요**")

        if self.user_interaction == "NONE":
            explanations.append("⚡ **사용자 개입 불필요** (피해자 클릭 없이 자율 실행)")
        elif self.user_interaction == "REQUIRED":
            explanations.append("🖱️ **사용자 유도 필요** (피싱 링크/파일 실행 필요)")

        if self.scope == "CHANGED":
            explanations.append("💥 **영향 범위 확장** (컨테이너/VM 탈출 등 다른 영역 침해 가능)")

        return " | ".join(explanations) if explanations else "공격 벡터 분석 정보 없음"


@dataclass
class VulnerabilityItem:
    cve_id: str
    description: str
    published_date: str
    cvss: CVSSInfo
    cwe_id: str = "NVD-CWE-noinfo"
    cwe_name: str = ""
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    is_cisa_kev: bool = False
    kev_action: str = ""
    related_news: List[Dict[str, str]] = field(default_factory=list)

    @property
    def severity_badge(self) -> str:
        if self.cvss.severity == "CRITICAL" or self.cvss.base_score >= 9.0:
            return "🔴 CRITICAL"
        elif self.cvss.severity == "HIGH" or self.cvss.base_score >= 7.0:
            return "🟠 HIGH"
        elif self.cvss.severity == "MEDIUM":
            return "🟡 MEDIUM"
        return "⚪ LOW"


@dataclass
class NewsItem:
    title: str
    link: str
    published: str
    source: str
    summary: str
    mentioned_cves: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


# =====================================================================
# 상태 저장소 (중복 방지 State Manager)
# =====================================================================

class StateTracker:
    """수집한 CVE와 뉴스 URL을 JSON에 저장하여 중복 알림을 방지"""

    def __init__(self, state_file: str = "cve_monitor_state.json"):
        self.state_file = state_file
        self.state = {
            "processed_cves": {},
            "processed_news": {}
        }
        self._load_state()

    def _load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    self.state = json.load(f)
                    if "processed_cves" not in self.state:
                        self.state["processed_cves"] = {}
                    if "processed_news" not in self.state:
                        self.state["processed_news"] = {}
            except Exception as e:
                logger.warning(f"상태 파일 로드 중 경고 ({e}), 새 상태로 시작합니다.")

    def _save_state(self):
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"상태 파일 저장 실패: {e}")

    def is_cve_seen(self, cve_id: str) -> bool:
        return cve_id in self.state["processed_cves"]

    def mark_cve_seen(self, cve_id: str, score: float, severity: str):
        self.state["processed_cves"][cve_id] = {
            "base_score": score,
            "severity": severity,
            "discovered_at": datetime.now().isoformat()
        }
        self._save_state()

    def is_news_seen(self, link: str) -> bool:
        return link in self.state["processed_news"]

    def mark_news_seen(self, link: str, title: str, source: str):
        self.state["processed_news"][link] = {
            "title": title,
            "source": source,
            "discovered_at": datetime.now().isoformat()
        }
        self._save_state()


# =====================================================================
# NIST NVD API v2.0 수집기
# =====================================================================

class NVDCollector:
    """NIST NVD REST API v2.0 클라이언트"""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 20):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout

    def fetch_recent_high_cves(
        self, days: int = 1, min_score: float = 7.0
    ) -> List[VulnerabilityItem]:
        """최근 등록 및 수정된 High/Critical 취약점 수집"""
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=days)

        pub_start = start_time.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": 100,
        }

        url = f"{self.BASE_URL}?{urllib.parse.urlencode(params)}"
        headers = {
            "User-Agent": "CyberSecurity-Vulnerability-Monitor/2.0"
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        logger.info(f"NVD API 호출 중: 최근 {days}일 간 취약점 조회 (URL: {url[:80]}...)")

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.warning(f"NVD API 호출 실패 ({e}). 오프라인/재시도 모드로 전환하거나 API 키를 확인하세요.")
            return []

        cve_items = data.get("vulnerabilities", [])
        logger.info(f"NVD 총 응답 항목 수: {len(cve_items)}개")

        results: List[VulnerabilityItem] = []
        for wrapper in cve_items:
            cve_data = wrapper.get("cve", {})
            parsed = self._parse_cve_item(cve_data)
            if parsed and parsed.cvss.base_score >= min_score:
                results.append(parsed)

        results.sort(key=lambda x: x.cvss.base_score, reverse=True)
        return results

    def _parse_cve_item(self, cve: Dict[str, Any]) -> Optional[VulnerabilityItem]:
        cve_id = cve.get("id", "UNKNOWN-CVE")
        published = cve.get("published", "")

        descriptions = cve.get("descriptions", [])
        desc_text = "설명 정보 없음"
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_info = CVSSInfo()

        cvss_sources = (
            metrics.get("cvssMetricV31", []) or
            metrics.get("cvssMetricV30", []) or
            metrics.get("cvssMetricV40", [])
        )

        if cvss_sources:
            primary_metric = cvss_sources[0].get("cvssData", {})
            cvss_info.version = primary_metric.get("version", "3.1")
            cvss_info.base_score = float(primary_metric.get("baseScore", 0.0))
            cvss_info.severity = primary_metric.get("baseSeverity", "UNKNOWN").upper()
            cvss_info.vector_string = primary_metric.get("vectorString", "")
            cvss_info.attack_vector = primary_metric.get("attackVector", "UNKNOWN").upper()
            cvss_info.privileges_required = primary_metric.get("privilegesRequired", "UNKNOWN").upper()
            cvss_info.user_interaction = primary_metric.get("userInteraction", "UNKNOWN").upper()
            cvss_info.scope = primary_metric.get("scope", "UNKNOWN").upper()

        cwe_id = "NVD-CWE-noinfo"
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwe_id = val
                    break

        affected = []
        configs = cve.get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_uri = match.get("criteria", "")
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        vendor, product = parts[3], parts[4]
                        item_str = f"{vendor}:{product}"
                        if item_str not in affected:
                            affected.append(item_str)

        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")][:3]

        return VulnerabilityItem(
            cve_id=cve_id,
            description=desc_text,
            published_date=published,
            cvss=cvss_info,
            cwe_id=cwe_id,
            affected_products=affected[:5],
            references=refs,
        )


# =====================================================================
# CISA KEV (Known Exploited Vulnerabilities) 연동기
# =====================================================================

class CISA_KEV_Client:
    """미국 CISA KEV 목록(실제 야생에서 공격에 활발히 쓰이는 취약점) 조회"""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    @classmethod
    def fetch_kev_map(cls, timeout: int = 15) -> Dict[str, Dict[str, str]]:
        logger.info("CISA KEV (Known Exploited Vulnerabilities) 카탈로그 확인 중...")
        try:
            req = urllib.request.Request(cls.KEV_URL, headers={"User-Agent": "CyberSecurity-Monitor"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                kev_dict = {}
                for v in data.get("vulnerabilities", []):
                    cve_id = v.get("cveID")
                    if cve_id:
                        kev_dict[cve_id] = {
                            "vendor": v.get("vendorProject", ""),
                            "product": v.get("product", ""),
                            "short_desc": v.get("shortDescription", ""),
                            "action": v.get("requiredAction", "패치 적용 필수"),
                            "due_date": v.get("dueDate", ""),
                        }
                logger.info(f"CISA KEV 총 {len(kev_dict)}개 취약점 로드 완료")
                return kev_dict
        except Exception as e:
            logger.warning(f"CISA KEV 로드 실패 ({e}), KEV 플래그 검사 생략")
            return {}


# =====================================================================
# 보안 뉴스 RSS 어그리게이터
# =====================================================================

class SecurityNewsCollector:
    """글로벌 및 국내 주요 보안 언론사 RSS 수집 및 취약점 연계 분석"""

    FEEDS = [
        {
            "name": "The Hacker News",
            "url": "https://feeds.feedburner.com/TheHackersNews",
            "lang": "en"
        },
        {
            "name": "BleepingComputer",
            "url": "https://www.bleepingcomputer.com/feed/",
            "lang": "en"
        },
        {
            "name": "SecurityWeek",
            "url": "https://feeds.feedburner.com/securityweek",
            "lang": "en"
        },
        {
            "name": "보안뉴스 (BoanNews)",
            "url": "https://www.boannews.com/media/news_rss.xml",
            "lang": "kr"
        },
        {
            "name": "KrCERT/CC 보안공지 (KISA)",
            "url": "https://www.krcert.or.kr/kr/bbs/rss.do?bbsId=B0000046",
            "lang": "kr"
        }
    ]

    CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    THREAT_KEYWORDS = {
        "Zero-Day": [r"zero-day", r"0-day", r"제로데이"],
        "RCE": [r"remote code execution", r"rce", r"원격 코드 실행"],
        "PoC Released": [r"proof of concept", r"poc", r"공격 코드 공개"],
        "Active Exploit": [r"actively exploited", r"in the wild", r"악용", r"침해사고"],
        "Privilege Escalation": [r"privilege escalation", r"권한 상승"],
        "Ransomware": [r"ransomware", r"랜섬웨어"],
    }

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def fetch_all_news(self, max_items_per_feed: int = 10) -> List[NewsItem]:
        all_news = []
        for feed in self.FEEDS:
            items = self._fetch_feed(feed["name"], feed["url"], max_items_per_feed)
            all_news.extend(items)
        logger.info(f"보안 뉴스 총 {len(all_news)}건 수집 완료")
        return all_news

    def _fetch_feed(self, source_name: str, feed_url: str, limit: int) -> List[NewsItem]:
        logger.info(f"뉴스 피드 수집 중: {source_name}")
        items = []
        try:
            req = urllib.request.Request(
                feed_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                content = resp.read()

            for enc in ["utf-8", "euc-kr", "cp949"]:
                try:
                    xml_str = content.decode(enc)
                    root = ET.fromstring(xml_str)
                    break
                except UnicodeDecodeError:
                    continue
            else:
                root = ET.fromstring(content)

            channel = root.find("channel")
            entries = channel.findall("item") if channel is not None else root.findall("{http://www.w3.org/2005/Atom}entry")

            for entry in entries[:limit]:
                title = self._get_text(entry, "title")
                link = self._get_link(entry)
                pub_date = self._get_text(entry, "pubDate") or self._get_text(entry, "published") or self._get_text(entry, "updated")
                summary = self._clean_html(self._get_text(entry, "description") or self._get_text(entry, "summary"))

                text_corpus = f"{title} {summary}"
                cves = list(set(self.CVE_REGEX.findall(text_corpus)))
                tags = self._extract_tags(text_corpus)

                item = NewsItem(
                    title=title,
                    link=link,
                    published=pub_date,
                    source=source_name,
                    summary=summary[:250] + ("..." if len(summary) > 250 else ""),
                    mentioned_cves=cves,
                    tags=tags,
                )
                items.append(item)
        except Exception as e:
            logger.warning(f"피드 수집 실패: {source_name} ({e})")

        return items

    def _get_text(self, elem: ET.Element, tag_name: str) -> str:
        found = elem.find(tag_name)
        if found is not None and found.text:
            return found.text.strip()
        found = elem.find(f"{{http://www.w3.org/2005/Atom}}{tag_name}")
        if found is not None and found.text:
            return found.text.strip()
        return ""

    def _get_link(self, elem: ET.Element) -> str:
        link_elem = elem.find("link")
        if link_elem is not None:
            if link_elem.text:
                return link_elem.text.strip()
            href = link_elem.get("href")
            if href:
                return href.strip()
        return ""

    def _clean_html(self, raw_html: str) -> str:
        clean = re.sub(r"<[^>]+>", " ", raw_html)
        return " ".join(clean.split())

    def _extract_tags(self, text: str) -> List[str]:
        tags = []
        for tag_name, patterns in self.THREAT_KEYWORDS.items():
            for p in patterns:
                if re.search(r"\b" + p + r"\b", text, re.IGNORECASE):
                    tags.append(tag_name)
                    break
        return tags


# =====================================================================
# 분석 및 요약 엔진 (취준생 스터디/면접 대비 인사이트 생성)
# =====================================================================

class BriefingEngine:
    """NVD 취약점과 보안 뉴스를 결합하여 보안직무 관점의 일일 브리핑 생성"""

    CWE_MAP = {
        "CWE-787": ("Out-of-bounds Write", "메모리 경계 외 쓰기", "버퍼 오버플로우로 인한 임의 코드 실행(RCE) 및 서비스 거부"),
        "CWE-125": ("Out-of-bounds Read", "메모리 경계 외 읽기", "메모리 정보 유출, ASLR 등 보안 메커니즘 우회"),
        "CWE-89": ("SQL Injection", "SQL 인젝션", "데이터베이스 무단 열람, 변조 및 인증 우회"),
        "CWE-79": ("Cross-site Scripting", "XSS", "사용자 세션 탈취, 악성 스크립트 실행"),
        "CWE-94": ("Code Injection", "코드 인젝션", "서버 측 임의 명령/코드 실행"),
        "CWE-502": ("Deserialization of Untrusted Data", "안전하지 않은 역직렬화", "원격 코드 실행(RCE) 및 객체 변조"),
        "CWE-22": ("Path Traversal", "경로 조작/디렉터리 탐색", "중요 시스템 파일(/etc/passwd 등) 열람 및 권한 탈취"),
        "CWE-287": ("Improper Authentication", "부적절한 인증", "인증 우회 후 관리자 권한 획득"),
        "CWE-352": ("CSRF", "크로스사이트 요청 위조", "사용자 권한 도용을 통한 무단 트랜잭션 수행"),
        "CWE-862": ("Missing Authorization", "인가 누락", "수평/수직 권한 상승을 통한 비인가 자원 접근"),
    }

    @classmethod
    def correlate_and_enrich(
        cls,
        cves: List[VulnerabilityItem],
        news_items: List[NewsItem],
        kev_map: Dict[str, Dict[str, str]]
    ) -> Tuple[List[VulnerabilityItem], List[NewsItem]]:
        cve_dict = {item.cve_id: item for item in cves}

        for cve_id, item in cve_dict.items():
            if cve_id in kev_map:
                item.is_cisa_kev = True
                item.kev_action = kev_map[cve_id].get("action", "")

            if item.cwe_id in cls.CWE_MAP:
                eng, kr, impact = cls.CWE_MAP[item.cwe_id]
                item.cwe_name = f"{kr} ({eng}) - {impact}"

        for news in news_items:
            for cve_id in news.mentioned_cves:
                if cve_id in cve_dict:
                    cve_dict[cve_id].related_news.append({
                        "title": news.title,
                        "link": news.link,
                        "source": news.source
                    })

        return list(cve_dict.values()), news_items

    @classmethod
    def generate_markdown_report(
        cls,
        vulnerabilities: List[VulnerabilityItem],
        news: List[NewsItem],
        report_date: Optional[str] = None
    ) -> str:
        date_str = report_date or datetime.now().strftime("%Y년 %m월 %d일")
        lines = []

        lines.append(f"# 🛡️ 일일 보안 취약점 & 위협 인텔리전스 브리핑 ({date_str})")
        lines.append("> **보안업계 취준생 & 엔지니어를 위한 고위험 취약점(CVSS High/Critical) 및 주요 보안 뉴스 데일리 요약**\n")

        critical_count = sum(1 for v in vulnerabilities if v.cvss.severity == "CRITICAL" or v.cvss.base_score >= 9.0)
        high_count = sum(1 for v in vulnerabilities if (v.cvss.severity == "HIGH" or v.cvss.base_score >= 7.0) and v.cvss.base_score < 9.0)
        kev_count = sum(1 for v in vulnerabilities if v.is_cisa_kev)

        lines.append("## 📊 오늘 탐지된 핵심 지표")
        lines.append(f"- **🔴 Critical (9.0 ~ 10.0):** {critical_count}건")
        lines.append(f"- **🟠 High (7.0 ~ 8.9):** {high_count}건")
        lines.append(f"- **⚠️ CISA KEV (실제 침해사고 악용 확인):** {kev_count}건")
        lines.append(f"- **📰 연동 보안 뉴스 기사:** {len(news)}건\n")

        lines.append("## 🚨 NVD 공식 등재 고위험 취약점 분석 (CVSS ≥ 7.0)")
        if not vulnerabilities:
            lines.append("_최근 24시간 동안 신규 등재된 CVSS 7.0 이상 고위험 취약점이 없습니다._\n")
        else:
            for idx, vuln in enumerate(vulnerabilities[:10], 1):
                kev_badge = "🔥 **[CISA KEV 긴급 악용 확인]** " if vuln.is_cisa_kev else ""
                lines.append(f"### {idx}. {vuln.severity_badge} {kev_badge}`{vuln.cve_id}` (CVSS {vuln.cvss.base_score})")
                lines.append(f"- **공격 벡터 해석:** {vuln.cvss.explain_vector_kr()}")
                if vuln.cwe_name:
                    lines.append(f"- **취약점 유형(CWE):** `{vuln.cwe_id}` - {vuln.cwe_name}")
                else:
                    lines.append(f"- **취약점 유형(CWE):** `{vuln.cwe_id}`")
                if vuln.affected_products:
                    products_str = ", ".join(f"`{p}`" for p in vuln.affected_products[:3])
                    lines.append(f"- **영향 제품:** {products_str}")
                lines.append(f"- **취약점 설명:** {vuln.description}")

                lines.append(f"- **💡 취준생 실무/면접 체크포인트:**")
                if "RCE" in vuln.description or "execution" in vuln.description.lower():
                    lines.append("  - 🎯 **공격 관점:** 원격에서 셸 획득이 가능하므로 즉각적인 PoC 분석 및 방화벽/WAF 차단 룰셋 배포 우선순위 최고.")
                    lines.append("  - 🛡️ **방어 관점:** 최신 벤더 공식 보안 패치 권고 및 불필요한 포트/외부 노출 서비스 폐쇄 확인 필요.")
                elif "auth" in vuln.description.lower() or "bypass" in vuln.description.lower():
                    lines.append("  - 🎯 **공격 관점:** 인증 로직 우회 후 관리자 API 무단 접근 위험.")
                    lines.append("  - 🛡️ **방어 관점:** 세션 유효성 검증 및 다중 인증(MFA) 강제화 점검.")
                else:
                    lines.append(f"  - 🛡️ **방어 관점:** CVSS Vector `{vuln.cvss.vector_string}`를 기반으로 사내 자산 인벤토리 취약 버전 식별 및 긴급 보안 권고문 발행 대상.")

                if vuln.related_news:
                    lines.append("  - 📰 **관련 보도:**")
                    for rn in vuln.related_news:
                        lines.append(f"    - [{rn['source']}] [{rn['title']}]({rn['link']})")

                if vuln.references:
                    ref_links = " | ".join(f"[참고자료]({r})" for r in vuln.references[:2])
                    lines.append(f"- **상세 링크:** {ref_links}")
                lines.append("")

        lines.append("## 📰 주요 보안 뉴스 & 제로데이 동향")
        if not news:
            lines.append("_수집된 최근 보안 뉴스가 없습니다._\n")
        else:
            for item in news[:8]:
                tag_str = " ".join(f"`#{t}`" for t in item.tags) if item.tags else ""
                cve_str = " ".join(f"`{c}`" for c in item.mentioned_cves) if item.mentioned_cves else ""
                extra = f"{tag_str} {cve_str}".strip()
                extra_display = f" ({extra})" if extra else ""

                lines.append(f"- **[{item.source}]** [{item.title}]({item.link}){extra_display}")
                if item.summary:
                    lines.append(f"  > {item.summary[:150]}...")
            lines.append("")

        lines.append("## 🎓 취준생을 위한 데일리 스터디 가이드")
        lines.append("1. **보안관제 지원자:** 오늘의 Critical 취약점 포트 및 프로토콜을 확인하고, Snort/Suricata 탐지 시그니처 작성 아이디어 구상해보기.")
        lines.append("2. **취약점 진단/모의해킹 지원자:** CWE 유형별 취약한 코드 패턴(취약한 함수 호출, 검증 부재 등)을 파악하고 재현 시나리오(PoC) 흐름 이해하기.")
        lines.append("3. **보안기획/컨설팅 지원자:** CISA KEV 등재 건을 중심으로 패치 우선순위 산정 및 사내 취약점 조치 프로세스(ISMS-P 인증항목 2.10.1 취약점 점검 및 조치) 연결짓기.")

        return "\n".join(lines)


# =====================================================================
# 알림 발송 디스패처 (Discord, Slack, Telegram, 콘솔)
# =====================================================================

class Notifier:
    """메신저 및 웹훅으로 자동 브리핑 전송"""

    @staticmethod
    def send_discord(webhook_url: str, title: str, markdown_content: str) -> bool:
        if not webhook_url:
            return False
        logger.info("디스코드 웹훅 전송 중...")

        truncated_content = markdown_content[:1900]
        payload = {
            "username": "보안 취약점 & 뉴스 알리미",
            "content": f"**{title}**\n\n{truncated_content}"
        }

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "CyberSecurity-Notifier"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 204)
        except Exception as e:
            logger.error(f"디스코드 전송 실패: {e}")
            return False

    @staticmethod
    def send_slack(webhook_url: str, title: str, markdown_content: str) -> bool:
        if not webhook_url:
            return False
        logger.info("슬랙 웹훅 전송 중...")

        payload = {
            "text": f"*{title}*\n\n{markdown_content[:2800]}"
        }

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error(f"슬랙 전송 실패: {e}")
            return False

    @staticmethod
    def send_telegram(bot_token: str, chat_id: str, title: str, markdown_content: str) -> bool:
        if not bot_token or not chat_id:
            return False
        logger.info("텔레그램 메시지 전송 중...")

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        text = f"🛡️ *{title}*\n\n{markdown_content[:3800]}"

        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error(f"텔레그램 전송 실패: {e}")
            return False


# =====================================================================
# 목 데이터 생성기 (오프라인 테스트 및 데모용)
# =====================================================================

class MockDataProvider:
    """인터넷 미연결 또는 테스트 실행 시 사용하는 실제 최신 보안 위협 시뮬레이션 데이터"""

    @staticmethod
    def get_sample_cves() -> List[VulnerabilityItem]:
        return [
            VulnerabilityItem(
                cve_id="CVE-2026-21845",
                description="Apache Tomcat HTTP/2 request smuggling vulnerability allows remote unauthenticated attackers to bypass authentication and execute remote code via specially crafted frames.",
                published_date="2026-10-23T04:12:00.000",
                cvss=CVSSInfo(
                    version="3.1",
                    base_score=9.8,
                    severity="CRITICAL",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    attack_vector="NETWORK",
                    privileges_required="NONE",
                    user_interaction="NONE",
                    scope="UNCHANGED"
                ),
                cwe_id="CWE-94",
                affected_products=["apache:tomcat:10.1.20", "apache:tomcat:9.0.86"],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-21845", "https://tomcat.apache.org/security.html"],
                is_cisa_kev=True,
                kev_action="긴급 보안 패치 버전으로 업데이트 권고"
            ),
            VulnerabilityItem(
                cve_id="CVE-2026-30114",
                description="Microsoft Windows Remote Desktop Services authentication bypass vulnerability leading to SYSTEM privilege escalation.",
                published_date="2026-10-22T18:30:00.000",
                cvss=CVSSInfo(
                    version="3.1",
                    base_score=8.8,
                    severity="HIGH",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    attack_vector="NETWORK",
                    privileges_required="LOW",
                    user_interaction="NONE",
                    scope="UNCHANGED"
                ),
                cwe_id="CWE-287",
                affected_products=["microsoft:windows_server_2022", "microsoft:windows_11"],
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-30114"],
                is_cisa_kev=False
            ),
            VulnerabilityItem(
                cve_id="CVE-2026-19402",
                description="Linux Kernel eBPF subsystem out-of-bounds write allowing local privilege escalation to root.",
                published_date="2026-10-22T11:00:00.000",
                cvss=CVSSInfo(
                    version="3.1",
                    base_score=7.8,
                    severity="HIGH",
                    vector_string="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    attack_vector="LOCAL",
                    privileges_required="LOW",
                    user_interaction="NONE",
                    scope="UNCHANGED"
                ),
                cwe_id="CWE-787",
                affected_products=["linux:linux_kernel:6.8.0"],
                references=["https://kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.8.2"],
                is_cisa_kev=False
            )
        ]

    @staticmethod
    def get_sample_news() -> List[NewsItem]:
        return [
            NewsItem(
                title="Critical Apache Tomcat Flaw Under Active Exploitation (CVE-2026-21845)",
                link="https://thehackernews.com/2026/10/critical-apache-tomcat-flaw.html",
                published="Fri, 23 Oct 2026 08:30:00 GMT",
                source="The Hacker News",
                summary="Security researchers have observed threat actors weaponizing the newly disclosed CVE-2026-21845 in Tomcat servers.",
                mentioned_cves=["CVE-2026-21845"],
                tags=["RCE", "Active Exploit", "PoC Released"]
            ),
            NewsItem(
                title="KISA, 최근 발견된 웹 서버 취약점 관련 긴급 보안 권고 발표",
                link="https://www.boannews.com/media/view.asp?idx=130000",
                published="2026-10-23 09:15:00",
                source="보안뉴스 (BoanNews)",
                summary="한국인터넷진흥원(KISA)은 톰캣 및 윈도우 원격 데스크톱 관련 고위험 취약점에 대한 국내 기업들의 신속한 패치를 당부했다.",
                mentioned_cves=["CVE-2026-21845", "CVE-2026-30114"],
                tags=["Active Exploit"]
            ),
            NewsItem(
                title="New Linux Kernel eBPF Zero-Day Exploit PoC Published on GitHub",
                link="https://www.bleepingcomputer.com/news/security/linux-ebpf-exploit-poc/",
                published="Thu, 22 Oct 2026 14:00:00 GMT",
                source="BleepingComputer",
                summary="A working Proof of Concept (PoC) exploit for CVE-2026-19402 has surfaced online, making kernel patching urgent.",
                mentioned_cves=["CVE-2026-19402"],
                tags=["PoC Released", "Privilege Escalation"]
            )
        ]


# =====================================================================
# 메인 파이프라인 컨트롤러
# =====================================================================

def run_pipeline(
    days: int = 1,
    min_score: float = 7.0,
    output_path: Optional[str] = None,
    use_mock: bool = False,
    discord_webhook: Optional[str] = None,
    slack_webhook: Optional[str] = None,
    telegram_token: Optional[str] = None,
    telegram_chat_id: Optional[str] = None,
    dry_run: bool = False
) -> str:
    """전체 수집·분석·알림 파이프라인 실행"""
    logger.info("=" * 60)
    logger.info(f"보안 취약점 & 뉴스 자동화 모니터링 시작 (최근 {days}일, CVSS ≥ {min_score})")
    logger.info("=" * 60)

    tracker = StateTracker()

    if use_mock:
        logger.info("🧪 [테스트 모드] 시뮬레이션용 최신 위협 데이터셋 사용")
        cves = MockDataProvider.get_sample_cves()
        news = MockDataProvider.get_sample_news()
        kev_map = {
            "CVE-2026-21845": {"action": "CISA 긴급 패치 권고", "vendor": "Apache"}
        }
    else:
        # 1. NVD 취약점 수집
        nvd = NVDCollector()
        cves = nvd.fetch_recent_high_cves(days=days, min_score=min_score)

        # 2. CISA KEV 수집
        kev_map = CISA_KEV_Client.fetch_kev_map()

        # 3. 보안 뉴스 수집
        news_collector = SecurityNewsCollector()
        news = news_collector.fetch_all_news()

        # 외부 네트워크 차단 환경 대비 폴백
        if not cves and not news:
            logger.warning("외부 네트워크로부터 데이터를 가져오지 못했습니다. 데모/테스트 데이터를 로드합니다.")
            cves = MockDataProvider.get_sample_cves()
            news = MockDataProvider.get_sample_news()
            kev_map = {"CVE-2026-21845": {"action": "CISA 긴급 패치 권고"}}

    # 중복 제거 (이미 알림 발송한 내역 필터링)
    new_cves = []
    for c in cves:
        if dry_run or not tracker.is_cve_seen(c.cve_id):
            new_cves.append(c)
        else:
            logger.debug(f"이미 처리된 CVE 스킵: {c.cve_id}")

    new_news = []
    for n in news:
        if dry_run or not tracker.is_news_seen(n.link):
            new_news.append(n)

    logger.info(f"신규 처리 대상: CVE {len(new_cves)}건, 뉴스 {len(new_news)}건")

    # 4. 연관성 분석 및 브리핑 생성
    enriched_cves, enriched_news = BriefingEngine.correlate_and_enrich(
        new_cves if new_cves else cves,
        new_news if new_news else news,
        kev_map
    )

    report_markdown = BriefingEngine.generate_markdown_report(enriched_cves, enriched_news)

    # 5. 파일 저장
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_markdown)
        logger.info(f"📄 마크다운 보고서 저장 완료: {output_path}")

    # 6. 알림 발송
    today_str = datetime.now().strftime("%Y-%m-%d")
    brief_title = f"🛡️ 데일리 보안 취약점 & 위협 인텔리전스 ({today_str})"

    discord_url = discord_webhook or os.getenv("DISCORD_WEBHOOK_URL")
    slack_url = slack_webhook or os.getenv("SLACK_WEBHOOK_URL")
    tg_token = telegram_token or os.getenv("TELEGRAM_BOT_TOKEN")
    tg_chat = telegram_chat_id or os.getenv("TELEGRAM_CHAT_ID")

    if discord_url:
        Notifier.send_discord(discord_url, brief_title, report_markdown)
    if slack_url:
        Notifier.send_slack(slack_url, brief_title, report_markdown)
    if tg_token and tg_chat:
        Notifier.send_telegram(tg_token, tg_chat, brief_title, report_markdown)

    # 7. 처리 상태 저장
    if not dry_run:
        for c in enriched_cves:
            tracker.mark_cve_seen(c.cve_id, c.cvss.base_score, c.cvss.severity)
        for n in enriched_news:
            tracker.mark_news_seen(n.link, n.title, n.source)

    return report_markdown


# =====================================================================
# CLI 인터페이스
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="보안업계 취준생을 위한 NVD 고위험 취약점 & 보안 뉴스 자동 수집·정리 시스템"
    )
    parser.add_argument("--days", type=int, default=1, help="조회할 최근 일수 (기본값: 1일)")
    parser.add_argument("--cvss-min", type=float, default=7.0, help="최소 CVSS 위험 점수 필터 (기본값: 7.0 High)")
    parser.add_argument("--output", "-o", type=str, default="daily_security_briefing.md", help="결과를 저장할 마크다운 파일 경로")
    parser.add_argument("--test", action="store_true", help="샘플 목 데이터로 시스템 기능 및 보고서 서식 테스트")
    parser.add_argument("--dry-run", action="store_true", help="DB에 상태를 저장하지 않고 1회성 출력")
    parser.add_argument("--discord", type=str, default=None, help="디스코드 웹훅 URL")
    parser.add_argument("--slack", type=str, default=None, help="슬랙 웹훅 URL")
    parser.add_argument("--telegram-token", type=str, default=None, help="텔레그램 봇 토큰")
    parser.add_argument("--telegram-chat-id", type=str, default=None, help="텔레그램 채팅방 ID")

    args = parser.parse_args()

    report = run_pipeline(
        days=args.days,
        min_score=args.cvss_min,
        output_path=args.output,
        use_mock=args.test,
        discord_webhook=args.discord,
        slack_webhook=args.slack,
        telegram_token=args.telegram_token,
        telegram_chat_id=args.telegram_chat_id,
        dry_run=args.dry_run
    )

    print("\n" + "=" * 30 + " [생성된 브리핑 미리보기] " + "=" * 30)
    print(report[:1500] + "\n... (생략) ...\n")
    print(f"✅ 실행 완료! 저장된 보고서: {args.output}")


if __name__ == "__main__":
    main()