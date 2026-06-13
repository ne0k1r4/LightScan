"""
i18n — internationalization layer for LightScan CLI output.

Supports: English (en), Chinese Simplified (zh), Russian (ru), Arabic (ar), Spanish (es).

Usage:
    from lightscan.i18n import t, set_lang
    set_lang("zh")
    print(t("scan.start"))        # 正在扫描
    print(t("open", port=443))    # 端口 443 开放

Language is auto-detected from $LIGHTSCAN_LANG or $LANG environment variables,
and can be overridden with --lang on the CLI.
"""
from __future__ import annotations
import os
from typing import Dict

# ── Translation table ─────────────────────────────────────────────────────────
_T: Dict[str, Dict[str, str]] = {

    # ── Scan output ───────────────────────────────────────────────────────────
    "scan.start": {
        "en": "Scanning {n} host(s) × {p} port(s) | concurrency={c}",
        "zh": "扫描 {n} 个主机 × {p} 个端口 | 并发={c}",
        "ru": "Сканирую {n} хост(ов) × {p} порт(ов) | параллельно={c}",
        "ar": "فحص {n} مضيف × {p} منفذ | التزامن={c}",
        "es": "Escaneando {n} host(s) × {p} puerto(s) | concurrencia={c}",
    },
    "scan.open": {
        "en": "OPEN  {host}:{port:<6} {detail}",
        "zh": "开放  {host}:{port:<6} {detail}",
        "ru": "ОТКРЫТ  {host}:{port:<6} {detail}",
        "ar": "مفتوح  {host}:{port:<6} {detail}",
        "es": "ABIERTO  {host}:{port:<6} {detail}",
    },
    "scan.done": {
        "en": "{n} findings  |  {crit} CRITICAL  |  {high} HIGH  |  {elapsed:.1f}s",
        "zh": "{n} 个发现  |  {crit} 严重  |  {high} 高危  |  {elapsed:.1f}秒",
        "ru": "{n} находок  |  {crit} КРИТИЧЕСКИХ  |  {high} ВЫСОКИХ  |  {elapsed:.1f}с",
        "ar": "{n} نتائج  |  {crit} حرجة  |  {high} عالية  |  {elapsed:.1f}ث",
        "es": "{n} hallazgos  |  {crit} CRÍTICOS  |  {high} ALTOS  |  {elapsed:.1f}s",
    },

    # ── Active scan ───────────────────────────────────────────────────────────
    "active.discovery": {
        "en": "Phase 1 — Host discovery ({n} targets)",
        "zh": "阶段1 — 主机发现（{n} 个目标）",
        "ru": "Фаза 1 — Обнаружение хостов ({n} целей)",
        "ar": "المرحلة 1 — اكتشاف المضيفين ({n} هدف)",
        "es": "Fase 1 — Descubrimiento de hosts ({n} objetivos)",
    },
    "active.alive": {
        "en": "ALIVE  {host}  [{method}] rtt={rtt}ms",
        "zh": "存活  {host}  [{method}] 延迟={rtt}ms",
        "ru": "АКТИВЕН  {host}  [{method}] задержка={rtt}мс",
        "ar": "نشط  {host}  [{method}] زمن_الاستجابة={rtt}ms",
        "es": "ACTIVO  {host}  [{method}] rtt={rtt}ms",
    },
    "active.portscan": {
        "en": "Phase 2 — Port scan ({n} host(s) × {p} ports)",
        "zh": "阶段2 — 端口扫描（{n} 个主机 × {p} 个端口）",
        "ru": "Фаза 2 — Сканирование портов ({n} хост(ов) × {p} портов)",
        "ar": "المرحلة 2 — فحص المنافذ ({n} مضيف × {p} منفذ)",
        "es": "Fase 2 — Escaneo de puertos ({n} host(s) × {p} puertos)",
    },
    "active.probing": {
        "en": "Phase 3 — Deep service probing",
        "zh": "阶段3 — 深度服务探测",
        "ru": "Фаза 3 — Глубокое зондирование сервисов",
        "ar": "المرحلة 3 — فحص الخدمات بعمق",
        "es": "Fase 3 — Sondeo profundo de servicios",
    },
    "active.vuln": {
        "en": "Phase 4 — Vulnerability validation",
        "zh": "阶段4 — 漏洞验证",
        "ru": "Фаза 4 — Проверка уязвимостей",
        "ar": "المرحلة 4 — التحقق من الثغرات",
        "es": "Fase 4 — Validación de vulnerabilidades",
    },
    "active.pivot": {
        "en": "Phase 5 — Pivot & exploit chain analysis",
        "zh": "阶段5 — 横向移动与漏洞利用链分析",
        "ru": "Фаза 5 — Анализ цепочек эксплойтов и пивотов",
        "ar": "المرحلة 5 — تحليل سلاسل الاستغلال والانتقال",
        "es": "Fase 5 — Análisis de cadenas de exploit y pivote",
    },
    "active.done": {
        "en": "Active scan complete — {n} findings | {crit} CRITICAL | {high} HIGH",
        "zh": "主动扫描完成 — {n} 个发现 | {crit} 严重 | {high} 高危",
        "ru": "Активное сканирование завершено — {n} находок | {crit} КРИТИЧЕСКИХ | {high} ВЫСОКИХ",
        "ar": "اكتمل الفحص النشط — {n} نتائج | {crit} حرجة | {high} عالية",
        "es": "Escaneo activo completo — {n} hallazgos | {crit} CRÍTICOS | {high} ALTOS",
    },

    # ── Autonomous mode ───────────────────────────────────────────────────────
    "auto.start": {
        "en": "Starting autonomous engagement: {domain}",
        "zh": "启动自主渗透测试：{domain}",
        "ru": "Запускаю автономное тестирование: {domain}",
        "ar": "بدء الاختبار التلقائي: {domain}",
        "es": "Iniciando prueba de penetración autónoma: {domain}",
    },
    "auto.stage": {
        "en": "Stage {n} — {name}",
        "zh": "阶段 {n} — {name}",
        "ru": "Этап {n} — {name}",
        "ar": "المرحلة {n} — {name}",
        "es": "Etapa {n} — {name}",
    },
    "auto.scope_drop": {
        "en": "[SCOPE] Dropped {n} out-of-scope host(s)",
        "zh": "[范围] 丢弃 {n} 个超出范围的主机",
        "ru": "[СКОУП] Исключено {n} хост(ов) за пределами области",
        "ar": "[النطاق] تم استبعاد {n} مضيف خارج النطاق",
        "es": "[ALCANCE] Descartados {n} host(s) fuera de alcance",
    },
    "auto.dc_found": {
        "en": "Domain Controller detected at {host} — Kerberos+LDAP",
        "zh": "检测到域控制器 {host} — Kerberos+LDAP",
        "ru": "Обнаружен контроллер домена {host} — Kerberos+LDAP",
        "ar": "تم اكتشاف متحكم المجال {host} — Kerberos+LDAP",
        "es": "Controlador de dominio detectado en {host} — Kerberos+LDAP",
    },
    "auto.done": {
        "en": "Autonomous scan complete — {n} findings | {crit} CRITICAL | DCs: {dcs} | {elapsed:.0f}s",
        "zh": "自主扫描完成 — {n} 个发现 | {crit} 严重 | 域控: {dcs} | {elapsed:.0f}秒",
        "ru": "Автономное сканирование завершено — {n} находок | {crit} КРИТИЧЕСКИХ | DC: {dcs} | {elapsed:.0f}с",
        "ar": "اكتمل الفحص التلقائي — {n} نتائج | {crit} حرجة | متحكمو النطاق: {dcs} | {elapsed:.0f}ث",
        "es": "Escaneo autónomo completo — {n} hallazgos | {crit} CRÍTICOS | DCs: {dcs} | {elapsed:.0f}s",
    },

    # ── Brute force ───────────────────────────────────────────────────────────
    "brute.start": {
        "en": "Brute force: {proto} | {n} host(s) | {u} users | {p} passwords",
        "zh": "爆破：{proto} | {n} 个主机 | {u} 个用户 | {p} 个密码",
        "ru": "Брутфорс: {proto} | {n} хост(ов) | {u} пользователей | {p} паролей",
        "ar": "التخمين: {proto} | {n} مضيف | {u} مستخدم | {p} كلمة مرور",
        "es": "Fuerza bruta: {proto} | {n} host(s) | {u} usuarios | {p} contraseñas",
    },
    "brute.found": {
        "en": "CREDENTIALS FOUND  {host}:{port} {proto} — {user}:{passwd}",
        "zh": "找到凭据  {host}:{port} {proto} — {user}:{passwd}",
        "ru": "НАЙДЕНЫ УЧЁТНЫЕ ДАННЫЕ  {host}:{port} {proto} — {user}:{passwd}",
        "ar": "تم العثور على بيانات الاعتماد  {host}:{port} {proto} — {user}:{passwd}",
        "es": "CREDENCIALES ENCONTRADAS  {host}:{port} {proto} — {user}:{passwd}",
    },
    "brute.locked": {
        "en": "Account locked: {user} — skipping",
        "zh": "账户锁定：{user} — 跳过",
        "ru": "Аккаунт заблокирован: {user} — пропускаю",
        "ar": "الحساب مقفل: {user} — تخطي",
        "es": "Cuenta bloqueada: {user} — omitiendo",
    },

    # ── CVE / Templates ───────────────────────────────────────────────────────
    "cve.start": {
        "en": "CVE + template checks | {n} host(s)",
        "zh": "CVE 与模板检查 | {n} 个主机",
        "ru": "Проверка CVE + шаблонов | {n} хост(ов)",
        "ar": "فحص CVE والقوالب | {n} مضيف",
        "es": "Comprobaciones CVE + plantillas | {n} host(s)",
    },
    "cve.vuln": {
        "en": "[{sev}] {module} @ {host}:{port} — {detail}",
        "zh": "[{sev}] {module} @ {host}:{port} — {detail}",
        "ru": "[{sev}] {module} @ {host}:{port} — {detail}",
        "ar": "[{sev}] {module} @ {host}:{port} — {detail}",
        "es": "[{sev}] {module} @ {host}:{port} — {detail}",
    },

    # ── Reports ───────────────────────────────────────────────────────────────
    "report.saved": {
        "en": "Report saved → {path}",
        "zh": "报告已保存 → {path}",
        "ru": "Отчёт сохранён → {path}",
        "ar": "تم حفظ التقرير → {path}",
        "es": "Informe guardado → {path}",
    },
    "report.compromise_map": {
        "en": "Compromise map saved → {path}",
        "zh": "渗透图谱已保存 → {path}",
        "ru": "Карта компрометации сохранена → {path}",
        "ar": "تم حفظ خريطة الاختراق → {path}",
        "es": "Mapa de compromiso guardado → {path}",
    },

    # ── General ───────────────────────────────────────────────────────────────
    "interrupted": {
        "en": "Interrupted — checkpoint saved",
        "zh": "已中断 — 检查点已保存",
        "ru": "Прервано — контрольная точка сохранена",
        "ar": "تمت المقاطعة — تم حفظ نقطة التفتيش",
        "es": "Interrumpido — punto de control guardado",
    },
    "no_targets": {
        "en": "No in-scope targets to scan.",
        "zh": "没有在范围内的扫描目标。",
        "ru": "Нет целей в пределах области сканирования.",
        "ar": "لا توجد أهداف ضمن النطاق للفحص.",
        "es": "No hay objetivos dentro del alcance para escanear.",
    },
    "stealth.on": {
        "en": "[OPSEC] Stealth mode — T1 timing, jitter, reduced concurrency",
        "zh": "[隐蔽] 隐身模式 — T1时序、抖动、降低并发",
        "ru": "[ОПСЕК] Скрытый режим — T1 тайминг, джиттер, снижена параллельность",
        "ar": "[أوبسيك] وضع التخفي — توقيت T1، اهتزاز، تزامن مخفض",
        "es": "[OPSEC] Modo sigiloso — tiempo T1, jitter, concurrencia reducida",
    },
    "chain.found": {
        "en": "Found {n} exploit chain(s)",
        "zh": "发现 {n} 条漏洞利用链",
        "ru": "Найдено {n} цепочек эксплойтов",
        "ar": "تم العثور على {n} سلسلة استغلال",
        "es": "Se encontraron {n} cadena(s) de exploit",
    },
    "pivot.found": {
        "en": "[PIVOT] {host} — {detail}",
        "zh": "[横移] {host} — {detail}",
        "ru": "[ПИВОТ] {host} — {detail}",
        "ar": "[انتقال] {host} — {detail}",
        "es": "[PIVOTE] {host} — {detail}",
    },
    "web.start": {
        "en": "Web scan: {url}",
        "zh": "Web扫描：{url}",
        "ru": "Сканирование веб: {url}",
        "ar": "فحص الويب: {url}",
        "es": "Escaneo web: {url}",
    },
    "dns.start": {
        "en": "DNS enumeration: {domain}",
        "zh": "DNS枚举：{domain}",
        "ru": "Перечисление DNS: {domain}",
        "ar": "تعداد DNS: {domain}",
        "es": "Enumeración DNS: {domain}",
    },
    "os.found": {
        "en": "[OS] {host} → {detail}",
        "zh": "[操作系统] {host} → {detail}",
        "ru": "[ОС] {host} → {detail}",
        "ar": "[نظام التشغيل] {host} → {detail}",
        "es": "[SO] {host} → {detail}",
    },
}

# ── Runtime language state ────────────────────────────────────────────────────

_SUPPORTED = {"en", "zh", "ru", "ar", "es"}
_LANG = "en"


def _detect_lang() -> str:
    """Auto-detect language from environment variables."""
    for var in ("LIGHTSCAN_LANG", "LANG", "LANGUAGE"):
        val = os.environ.get(var, "")
        if val:
            code = val.lower().split("_")[0].split(".")[0]
            if code in _SUPPORTED:
                return code
    return "en"


def set_lang(lang: str):
    """Override the active language. Call before any t() calls."""
    global _LANG
    lang = lang.lower().strip()
    if lang in _SUPPORTED:
        _LANG = lang
    else:
        _LANG = "en"


def get_lang() -> str:
    return _LANG


def t(key: str, **kwargs) -> str:
    """
    Look up a translation string and format it with kwargs.

    Falls back to English if the key or language is missing.
    Falls back to the raw key if even English is missing.

    Example:
        t("scan.done", n=42, crit=3, high=7, elapsed=12.4)
    """
    entry = _T.get(key)
    if entry is None:
        return key.format(**kwargs) if kwargs else key
    text = entry.get(_LANG) or entry.get("en") or key
    try:
        return text.format(**kwargs)
    except (KeyError, IndexError):
        return text


# Auto-detect on import
_LANG = _detect_lang()
