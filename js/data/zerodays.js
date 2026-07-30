const ZERO_DAYS = {
  "version": 8,
  "items": [
    {
      "n": 1,
      "id": "zd-01",
      "cve": "CVE-2026-46242",
      "product": "Linux kernel (epoll)",
      "cwe": "Race condition + UAF",
      "category": "kernel",
      "category_en": "OS / Kernel",
      "category_ru": "ОС и ядра",
      "summary_en": "Local unprivileged user → root via race in ep_remove(); reachable from Chrome renderer sandbox.",
      "summary_ru": "Локальный непривилегированный пользователь → root через гонку в ep_remove(); достижимо из sandbox Chrome-рендерера.",
      "practice": "race",
      "owasp_note": "—",
      "flag": "FLAG{zd_01_202646242}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Local unprivileged user → root via race in ep_remove(); reachable from Chrome renderer sandbox.</p>\n<h3>Also known as</h3>\n<p>Bad Epoll</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-46242 · <strong>Product:</strong> Linux kernel (epoll) · <strong>Class:</strong> Race condition + UAF</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Concurrent epoll operations free kernel structures while still in use (UAF). Winning the race enables credential overwrite. Dangerous as a sandbox-escape step after browser renderer RCE.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Локальный непривилегированный пользователь → root через гонку в ep_remove(); достижимо из sandbox Chrome-рендерера.</p>\n<h3>Также известно как</h3>\n<p>Bad Epoll</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-46242 · <strong>Продукт:</strong> Linux kernel (epoll) · <strong>Класс:</strong> Race condition + UAF</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Параллельные операции epoll освобождают структуры ядра, пока они ещё используются (UAF). Выигрыш гонки → overwrite creds. Опасно как sandbox-escape после renderer RCE.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 2,
      "id": "zd-02",
      "cve": "CVE-2026-31431",
      "product": "Linux kernel (AF_ALG)",
      "cwe": "Logic error / scatterlist",
      "category": "kernel",
      "category_en": "OS / Kernel",
      "category_ru": "ОС и ядра",
      "summary_en": "LPE via page-cache corruption during in-place AEAD decryption; reported on distros with long-lived kernels (from ~2017 analyses).",
      "summary_ru": "LPE через порчу page cache при in-place AEAD-дешифровании; в разборах — широкая база ядер (~с 2017).",
      "practice": "lpe",
      "owasp_note": "—",
      "flag": "FLAG{zd_02_202631431}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>LPE via page-cache corruption during in-place AEAD decryption; reported on distros with long-lived kernels (from ~2017 analyses).</p>\n<h3>Also known as</h3>\n<p>Copy Fail</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-31431 · <strong>Product:</strong> Linux kernel (AF_ALG) · <strong>Class:</strong> Logic error / scatterlist</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>AF_ALG exposes kernel crypto to userspace. Flawed scatterlist handling corrupts cached pages shared with other processes — crypto API becomes LPE primitive.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>LPE через порчу page cache при in-place AEAD-дешифровании; в разборах — широкая база ядер (~с 2017).</p>\n<h3>Также известно как</h3>\n<p>Copy Fail</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-31431 · <strong>Продукт:</strong> Linux kernel (AF_ALG) · <strong>Класс:</strong> Logic error / scatterlist</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>AF_ALG отдаёт crypto userspace. Ошибочный scatterlist портит page cache, общий с другими процессами — crypto API становится LPE.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 3,
      "id": "zd-03",
      "cve": "CVE-2026-52969",
      "product": "Linux kernel (KVM)",
      "cwe": "Integer overflow / OOB read",
      "category": "kernel",
      "category_en": "OS / Kernel",
      "category_ru": "ОС и ядра",
      "summary_en": "Local process with /dev/kvm triggers u64 dirty-ring offset overflow → hypervisor memory corruption.",
      "summary_ru": "Локальный процесс с /dev/kvm вызывает переполнение u64-смещения dirty ring → повреждение памяти гипервизора.",
      "practice": "lpe",
      "owasp_note": "—",
      "flag": "FLAG{zd_03_202652969}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Local process with /dev/kvm triggers u64 dirty-ring offset overflow → hypervisor memory corruption.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-52969 · <strong>Product:</strong> Linux kernel (KVM) · <strong>Class:</strong> Integer overflow / OOB read</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Threatens VM/host isolation on multi-tenant KVM nodes. Requires ability to open KVM device node.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Локальный процесс с /dev/kvm вызывает переполнение u64-смещения dirty ring → повреждение памяти гипервизора.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-52969 · <strong>Продукт:</strong> Linux kernel (KVM) · <strong>Класс:</strong> Integer overflow / OOB read</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Угроза изоляции VM/host на multi-tenant KVM. Нужен доступ к device node KVM.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 4,
      "id": "zd-04",
      "cve": "CVE-2026-23226",
      "product": "Linux kernel",
      "cwe": "Improper privilege handling",
      "category": "kernel",
      "category_en": "OS / Kernel",
      "category_ru": "ОС и ядра",
      "summary_en": "Linux kernel LPE, CVSS 8.8.",
      "summary_ru": "LPE в Linux kernel, CVSS 8.8.",
      "practice": "lpe",
      "owasp_note": "—",
      "flag": "FLAG{zd_04_202623226}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Linux kernel LPE, CVSS 8.8.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-23226 · <strong>Product:</strong> Linux kernel · <strong>Class:</strong> Improper privilege handling</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>High CVSS local elev — patch with distro kernel stream; treat as standard KEV-class local risk once listed.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>LPE в Linux kernel, CVSS 8.8.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-23226 · <strong>Продукт:</strong> Linux kernel · <strong>Класс:</strong> Improper privilege handling</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Высокий CVSS local elev — патч в потоке дистрибутива; как только в KEV — стандартный local risk.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 5,
      "id": "zd-05",
      "cve": "CVE-2022-0492",
      "product": "Linux kernel (cgroups v1)",
      "cwe": "Missing authorization",
      "category": "kernel",
      "category_en": "OS / Kernel",
      "category_ru": "ОС и ядра",
      "summary_en": "Container escape / LPE via cgroup_release_agent_write(); added to CISA KEV June 2026 despite age.",
      "summary_ru": "Побег из контейнера / LPE через cgroup_release_agent_write(); в CISA KEV в июне 2026 несмотря на возраст.",
      "practice": "lpe",
      "owasp_note": "—",
      "flag": "FLAG{zd_05_20220492}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Container escape / LPE via cgroup_release_agent_write(); added to CISA KEV June 2026 despite age.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2022-0492 · <strong>Product:</strong> Linux kernel (cgroups v1) · <strong>Class:</strong> Missing authorization</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>On cgroup v1 with weak restrictions, writing release_agent + notify_on_release can execute a host binary as root when the cgroup is released. Long-tail unpatched systems remain targets.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Побег из контейнера / LPE через cgroup_release_agent_write(); в CISA KEV в июне 2026 несмотря на возраст.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2022-0492 · <strong>Продукт:</strong> Linux kernel (cgroups v1) · <strong>Класс:</strong> Missing authorization</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>На cgroup v1 без жёстких ограничений: write release_agent + notify_on_release → host binary от root. Long-tail unpatched системы остаются целями.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 6,
      "id": "zd-06",
      "cve": "CVE-2026-32202",
      "product": "Windows Shell",
      "cwe": "Improper auth (incomplete patch)",
      "category": "windows",
      "category_en": "Windows client / shell",
      "category_ru": "Windows (клиент / Shell)",
      "summary_en": "Zero-click NTLMv2 hash leak; incomplete fix of CVE-2026-21510; exploited by APT28 since Dec 2025.",
      "summary_ru": "Zero-click утечка NTLMv2; неполный патч CVE-2026-21510; APT28 с декабря 2025.",
      "practice": "ntlm",
      "owasp_note": "—",
      "flag": "FLAG{zd_06_202632202}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Zero-click NTLMv2 hash leak; incomplete fix of CVE-2026-21510; exploited by APT28 since Dec 2025.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-32202 · <strong>Product:</strong> Windows Shell · <strong>Class:</strong> Improper auth (incomplete patch)</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Shell resolves attacker-controlled resources triggering outbound NTLM. Captured hashes are cracked or relayed. Incomplete patches left residual risk — install full cumulatives.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Zero-click утечка NTLMv2; неполный патч CVE-2026-21510; APT28 с декабря 2025.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-32202 · <strong>Продукт:</strong> Windows Shell · <strong>Класс:</strong> Improper auth (incomplete patch)</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Shell резолвит attacker-controlled ресурсы → outbound NTLM. Хэши ломают/relay. Неполный патч оставил residual risk — только полные cumulative updates.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 7,
      "id": "zd-07",
      "cve": "CVE-2026-21510",
      "product": "Windows Shell",
      "cwe": "RCE",
      "category": "windows",
      "category_en": "Windows client / shell",
      "category_ru": "Windows (клиент / Shell)",
      "summary_en": "First link of APT28 chain (pre-February patch) — Windows Shell RCE.",
      "summary_ru": "Первое звено цепочки APT28 (pre-February патч) — RCE в Windows Shell.",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{zd_07_202621510}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>First link of APT28 chain (pre-February patch) — Windows Shell RCE.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-21510 · <strong>Product:</strong> Windows Shell · <strong>Class:</strong> RCE</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Used as initial client-side execution in espionage chains before February fixes. Later incomplete remediations fed related NTLM issues.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Первое звено цепочки APT28 (pre-February патч) — RCE в Windows Shell.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-21510 · <strong>Продукт:</strong> Windows Shell · <strong>Класс:</strong> RCE</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Initial client-side execution в шпионских цепочках до февральских фиксов. Неполная remediation породила связанные NTLM-проблемы.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 8,
      "id": "zd-08",
      "cve": "CVE-2026-21513",
      "product": "Windows (LNK/MSHTML)",
      "cwe": "Security feature bypass",
      "category": "windows",
      "category_en": "Windows client / shell",
      "category_ru": "Windows (клиент / Shell)",
      "summary_en": "Malicious .lnk loads a DLL from a remote UNC path.",
      "summary_ru": "Вредоносный .lnk загружает DLL с удалённого UNC-пути.",
      "practice": "path_trav",
      "owasp_note": "—",
      "flag": "FLAG{zd_08_202621513}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Malicious .lnk loads a DLL from a remote UNC path.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-21513 · <strong>Product:</strong> Windows (LNK/MSHTML) · <strong>Class:</strong> Security feature bypass</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Shortcut + MSHTML path bypasses intended security features to load remote code. Classic dual-use with phishing delivery.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Вредоносный .lnk загружает DLL с удалённого UNC-пути.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-21513 · <strong>Продукт:</strong> Windows (LNK/MSHTML) · <strong>Класс:</strong> Security feature bypass</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Shortcut + MSHTML обходит security features и грузит remote code. Классика вместе с phishing delivery.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 9,
      "id": "zd-09",
      "cve": "CVE-2026-20700",
      "product": "Apple dyld (iOS/iPadOS/macOS)",
      "cwe": "Memory corruption",
      "category": "apple",
      "category_en": "Apple platforms",
      "category_ru": "Apple (iOS / macOS)",
      "summary_en": "RCE via dynamic linker; Google TAG; commercial spyware chain component.",
      "summary_ru": "RCE через dyld; Google TAG; компонент цепочки commercial spyware.",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{zd_09_202620700}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>RCE via dynamic linker; Google TAG; commercial spyware chain component.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-20700 · <strong>Product:</strong> Apple dyld (iOS/iPadOS/macOS) · <strong>Class:</strong> Memory corruption</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Dynamic linker bugs are chain gold: after WebKit renderer compromise, dyld issues help break out to broader process/OS context. High-risk users need fastest Apple responses and Lockdown Mode.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>RCE через dyld; Google TAG; компонент цепочки commercial spyware.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-20700 · <strong>Продукт:</strong> Apple dyld (iOS/iPadOS/macOS) · <strong>Класс:</strong> Memory corruption</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Баги динамического линкера — золото для цепочек: после WebKit compromise dyld помогает выйти в более широкий process/OS context. High-risk — fastest Apple responses и Lockdown Mode.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 10,
      "id": "zd-10",
      "cve": "CVE-2025-48595",
      "product": "Android Framework",
      "cwe": "Integer overflow",
      "category": "android",
      "category_en": "Android",
      "category_ru": "Android",
      "summary_en": "LPE without user interaction; CISA KEV June 2026.",
      "summary_ru": "LPE без UI-взаимодействия; CISA KEV, июнь 2026.",
      "practice": "lpe",
      "owasp_note": "—",
      "flag": "FLAG{zd_10_202548595}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>LPE without user interaction; CISA KEV June 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-48595 · <strong>Product:</strong> Android Framework · <strong>Class:</strong> Integer overflow</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Framework-level integer overflow elevates a local attacker/malware without clicks. Mobile fleets with lagging patch levels are primary victims.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>LPE без UI-взаимодействия; CISA KEV, июнь 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-48595 · <strong>Продукт:</strong> Android Framework · <strong>Класс:</strong> Integer overflow</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Integer overflow уровня Framework поднимает local attacker/malware без кликов. Жертвы — флоты с отстающим patch level.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 11,
      "id": "zd-11",
      "cve": "CVE-2026-3910",
      "product": "Chrome V8",
      "cwe": "Type confusion / inappropriate implementation",
      "category": "browser",
      "category_en": "Browsers",
      "category_ru": "Браузеры",
      "summary_en": "RCE inside Chrome sandbox via crafted HTML (V8).",
      "summary_ru": "RCE в sandbox Chrome через crafted HTML (V8).",
      "practice": "rce_browser",
      "owasp_note": "—",
      "flag": "FLAG{zd_11_20263910}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>RCE inside Chrome sandbox via crafted HTML (V8).</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-3910 · <strong>Product:</strong> Chrome V8 · <strong>Class:</strong> Type confusion / inappropriate implementation</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Type confusion in the JS engine yields attacker-controlled code in the renderer. Full compromise usually needs a second sandbox-escape bug.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>RCE в sandbox Chrome через crafted HTML (V8).</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-3910 · <strong>Продукт:</strong> Chrome V8 · <strong>Класс:</strong> Type confusion / inappropriate implementation</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Type confusion в JS-движке → код атакующего в renderer. Полный компромисс обычно требует второго sandbox-escape.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 12,
      "id": "zd-12",
      "cve": "CVE-2026-3909",
      "product": "Chrome Skia",
      "cwe": "OOB write",
      "category": "browser",
      "category_en": "Browsers",
      "category_ru": "Браузеры",
      "summary_en": "OOB write in Skia graphics; same patch round as CVE-2026-3910.",
      "summary_ru": "OOB write в Skia; тот же патч-раунд, что CVE-2026-3910.",
      "practice": "rce_browser",
      "owasp_note": "—",
      "flag": "FLAG{zd_12_20263909}",
      "points": 12,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>OOB write in Skia graphics; same patch round as CVE-2026-3910.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-3909 · <strong>Product:</strong> Chrome Skia · <strong>Class:</strong> OOB write</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Graphics library bugs are classic drive-by surfaces — parsing images/canvas paths without trusting the site origin model alone.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>OOB write в Skia; тот же патч-раунд, что CVE-2026-3910.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-3909 · <strong>Продукт:</strong> Chrome Skia · <strong>Класс:</strong> OOB write</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Баги графических библиотек — классика drive-by: парсинг image/canvas вне «просто origin model сайта».</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 13,
      "id": "zd-13",
      "cve": "CVE-2026-5281",
      "product": "Chrome Dawn",
      "cwe": "Use-after-free",
      "category": "browser",
      "category_en": "Browsers",
      "category_ru": "Браузеры",
      "summary_en": "UAF in Dawn; sandbox escape via WebGPU abstraction.",
      "summary_ru": "UAF в Dawn; sandbox escape через WebGPU-абстракцию.",
      "practice": "uaf",
      "owasp_note": "—",
      "flag": "FLAG{zd_13_20265281}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>UAF in Dawn; sandbox escape via WebGPU abstraction.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-5281 · <strong>Product:</strong> Chrome Dawn · <strong>Class:</strong> Use-after-free</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>WebGPU/Dawn widens the attack surface between renderer and GPU process. UAF here is prized for escape after V8 RCE.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>UAF в Dawn; sandbox escape через WebGPU-абстракцию.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-5281 · <strong>Продукт:</strong> Chrome Dawn · <strong>Класс:</strong> Use-after-free</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>WebGPU/Dawn расширяет поверхность между renderer и GPU process. UAF здесь ценится для escape после V8 RCE.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 14,
      "id": "zd-14",
      "cve": "CVE-2026-11645",
      "product": "Chrome",
      "cwe": "Actively exploited (KEV)",
      "category": "browser",
      "category_en": "Browsers",
      "category_ru": "Браузеры",
      "summary_en": "Added to CISA KEV June 2026 — treat as emergency Chrome update.",
      "summary_ru": "В CISA KEV в июне 2026 — emergency update Chrome.",
      "practice": "rce_browser",
      "owasp_note": "—",
      "flag": "FLAG{zd_14_202611645}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Added to CISA KEV June 2026 — treat as emergency Chrome update.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-11645 · <strong>Product:</strong> Chrome · <strong>Class:</strong> Actively exploited (KEV)</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>KEV listing means observed exploitation. Do not wait for monthly rings if a fixed Stable build exists.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>В CISA KEV в июне 2026 — emergency update Chrome.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-11645 · <strong>Продукт:</strong> Chrome · <strong>Класс:</strong> Actively exploited (KEV)</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>KEV = наблюдаемая эксплуатация. Не ждать monthly rings, если есть fixed Stable.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 15,
      "id": "zd-15",
      "cve": "CVE-2025-14174",
      "product": "Apple WebKit",
      "cwe": "Memory corruption",
      "category": "browser",
      "category_en": "Browsers",
      "category_ru": "Браузеры",
      "summary_en": "WebKit memory corruption; part of targeted chain with dyld (#9).",
      "summary_ru": "Memory corruption WebKit; часть targeted-цепочки с dyld (#9).",
      "practice": "rce_browser",
      "owasp_note": "—",
      "flag": "FLAG{zd_15_202514174}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>WebKit memory corruption; part of targeted chain with dyld (#9).</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-14174 · <strong>Product:</strong> Apple WebKit · <strong>Class:</strong> Memory corruption</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>WebKit RCEs are the browser half of iOS spyware chains; paired with OS components for full device takeover.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Memory corruption WebKit; часть targeted-цепочки с dyld (#9).</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-14174 · <strong>Продукт:</strong> Apple WebKit · <strong>Класс:</strong> Memory corruption</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>WebKit RCE — браузерная половина iOS spyware chains; вместе с ОС-компонентами = full device takeover.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 16,
      "id": "zd-16",
      "cve": "CVE-2025-43529",
      "product": "Apple WebKit",
      "cwe": "Use-after-free",
      "category": "browser",
      "category_en": "Browsers",
      "category_ru": "Браузеры",
      "summary_en": "WebKit UAF → RCE on malicious web content.",
      "summary_ru": "UAF в WebKit → RCE на вредоносном веб-контенте.",
      "practice": "uaf",
      "owasp_note": "—",
      "flag": "FLAG{zd_16_202543529}",
      "points": 12,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>WebKit UAF → RCE on malicious web content.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-43529 · <strong>Product:</strong> Apple WebKit · <strong>Class:</strong> Use-after-free</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Affects Safari and embedded WebKit views. Patch OS; reduce unnecessary WebViews in enterprise apps.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>UAF в WebKit → RCE на вредоносном веб-контенте.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-43529 · <strong>Продукт:</strong> Apple WebKit · <strong>Класс:</strong> Use-after-free</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Safari и embedded WebKit views. Патч ОС; меньше лишних WebView в enterprise apps.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 17,
      "id": "zd-17",
      "cve": "CVE-2026-1281",
      "product": "Ivanti EPMM",
      "cwe": "Unauth RCE",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Unauthenticated RCE massively exploited; Unit42 campaigns US/DE/AU/CA.",
      "summary_ru": "Unauth RCE, массовая эксплуатация; кампании Unit42 US/DE/AU/CA.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_17_20261281}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Unauthenticated RCE massively exploited; Unit42 campaigns US/DE/AU/CA.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-1281 · <strong>Product:</strong> Ivanti EPMM · <strong>Class:</strong> Unauth RCE</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Mobile device management at the edge: unauth RCE means full control of management plane and enrolled devices. Conceptual auth-boundary failure (≈A01) but binary appliance stack, not your ORM app.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Unauth RCE, массовая эксплуатация; кампании Unit42 US/DE/AU/CA.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-1281 · <strong>Продукт:</strong> Ivanti EPMM · <strong>Класс:</strong> Unauth RCE</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>MDM на edge: unauth RCE = контроль management plane и enrolled devices. Концептуально auth-boundary (≈A01), но binary appliance, не ваш ORM.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 18,
      "id": "zd-18",
      "cve": "CVE-2026-1340",
      "product": "Ivanti EPMM",
      "cwe": "Unauth RCE",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Paired with CVE-2026-1281; both 0-day before disclosure.",
      "summary_ru": "Пара с CVE-2026-1281; обе 0-day до дисклоуза.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_18_20261340}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Paired with CVE-2026-1281; both 0-day before disclosure.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-1340 · <strong>Product:</strong> Ivanti EPMM · <strong>Class:</strong> Unauth RCE</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Dual unauth RCEs in the same product family amplify mass exploitation windows before patches ship.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Пара с CVE-2026-1281; обе 0-day до дисклоуза.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-1340 · <strong>Продукт:</strong> Ivanti EPMM · <strong>Класс:</strong> Unauth RCE</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Два unauth RCE в одном семействе продуктов расширяют окно массовой эксплуатации до патчей.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 19,
      "id": "zd-19",
      "cve": "CVE-2026-6973",
      "product": "Ivanti EPMM",
      "cwe": "Improper input validation",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "RCE requiring admin auth; chained after credential harvest from #17/#18.",
      "summary_ru": "RCE с admin-auth; цепочка после credential harvesting из #17/#18.",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_19_20266973}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>RCE requiring admin auth; chained after credential harvest from #17/#18.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-6973 · <strong>Product:</strong> Ivanti EPMM · <strong>Class:</strong> Improper input validation</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>After unauth foothold steals admin sessions/creds, authenticated input-validation RCE finishes full compromise.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>RCE с admin-auth; цепочка после credential harvesting из #17/#18.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-6973 · <strong>Продукт:</strong> Ivanti EPMM · <strong>Класс:</strong> Improper input validation</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>После unauth foothold и кражи admin-сессий authenticated RCE добивает компромисс.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 20,
      "id": "zd-20",
      "cve": "CVE-2026-7821",
      "product": "Ivanti EPMM",
      "cwe": "Unauth (Apple DEP)",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Relevant when Apple Device Enrollment is used.",
      "summary_ru": "Актуально при использовании Apple Device Enrollment.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_20_20267821}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Relevant when Apple Device Enrollment is used.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-7821 · <strong>Product:</strong> Ivanti EPMM · <strong>Class:</strong> Unauth (Apple DEP)</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>DEP-related unauth surface — only in-scope for orgs using Apple automated enrollment with Ivanti EPMM.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Актуально при использовании Apple Device Enrollment.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-7821 · <strong>Продукт:</strong> Ivanti EPMM · <strong>Класс:</strong> Unauth (Apple DEP)</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Unauth поверхность вокруг DEP — scope только если есть Apple automated enrollment + Ivanti EPMM.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 21,
      "id": "zd-21",
      "cve": "CVE-2026-10520",
      "product": "Ivanti Sentry",
      "cwe": "OS command injection",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "OS command injection; CISA KEV June 2026.",
      "summary_ru": "OS command injection; CISA KEV, июнь 2026.",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_21_202610520}",
      "points": 15,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>OS command injection; CISA KEV June 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-10520 · <strong>Product:</strong> Ivanti Sentry · <strong>Class:</strong> OS command injection</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Sentry sits in the mobile traffic path. Command injection on the appliance is RCE on a security gateway — high blast radius.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>OS command injection; CISA KEV, июнь 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-10520 · <strong>Продукт:</strong> Ivanti Sentry · <strong>Класс:</strong> OS command injection</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Sentry в пути mobile traffic. Command injection на appliance = RCE на security gateway — высокий blast radius.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 22,
      "id": "zd-22",
      "cve": "CVE-2026-24858",
      "product": "FortiCloud SSO / FortiOS family",
      "cwe": "Auth bypass",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "SSO account bypass; CVSS 9.8; exploitation before patch. Affects FortiOS, FortiProxy, FortiWeb, FortiAnalyzer, FortiManager.",
      "summary_ru": "Обход SSO между аккаунтами; CVSS 9.8; эксплуатация раньше патча. FortiOS/Proxy/Web/Analyzer/Manager.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_22_202624858}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>SSO account bypass; CVSS 9.8; exploitation before patch. Affects FortiOS, FortiProxy, FortiWeb, FortiAnalyzer, FortiManager.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-24858 · <strong>Product:</strong> FortiCloud SSO / FortiOS family · <strong>Class:</strong> Auth bypass</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Broken SSO trust between Fortinet cloud/accounts yields high-privilege access without valid credentials — classic auth boundary failure on edge appliances.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Обход SSO между аккаунтами; CVSS 9.8; эксплуатация раньше патча. FortiOS/Proxy/Web/Analyzer/Manager.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-24858 · <strong>Продукт:</strong> FortiCloud SSO / FortiOS family · <strong>Класс:</strong> Auth bypass</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Сломанный SSO trust Fortinet cloud/accounts → high-priv доступ без валидных creds — auth boundary failure на edge appliance.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 23,
      "id": "zd-23",
      "cve": "CVE-2025-59718",
      "product": "FortiOS / related",
      "cwe": "Auth bypass",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Disclosed Dec 2025 with the broader Fortinet auth-bypass family.",
      "summary_ru": "Раскрыта в декабре 2025 вместе с семейством Fortinet auth bypass.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_23_202559718}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Disclosed Dec 2025 with the broader Fortinet auth-bypass family.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-59718 · <strong>Product:</strong> FortiOS / related · <strong>Class:</strong> Auth bypass</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Part of the late-2025 Fortinet authentication failure wave; pair with inventory of exposed management interfaces.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Раскрыта в декабре 2025 вместе с семейством Fortinet auth bypass.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-59718 · <strong>Продукт:</strong> FortiOS / related · <strong>Класс:</strong> Auth bypass</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Часть волны auth-fail Fortinet конца 2025; вместе с inventory exposed management interfaces.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 24,
      "id": "zd-24",
      "cve": "CVE-2026-35616",
      "product": "FortiClientEMS",
      "cwe": "Improper access control",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Pre-auth API bypass → arbitrary code; holiday hotfix window.",
      "summary_ru": "Pre-auth API bypass → произвольный код; hotfix в праздники.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_24_202635616}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Pre-auth API bypass → arbitrary code; holiday hotfix window.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-35616 · <strong>Product:</strong> FortiClientEMS · <strong>Class:</strong> Improper access control</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Endpoint management servers are crown jewels: pre-auth API to RCE means mass agent compromise.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Pre-auth API bypass → произвольный код; hotfix в праздники.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-35616 · <strong>Продукт:</strong> FortiClientEMS · <strong>Класс:</strong> Improper access control</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Endpoint management — crown jewel: pre-auth API → RCE = массовый компромисс агентов.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 25,
      "id": "zd-25",
      "cve": "CVE-2025-58034",
      "product": "FortiWeb",
      "cwe": "OS command injection",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Authenticated RCE; likely chained with earlier FortiWeb bugs.",
      "summary_ru": "Authenticated RCE; вероятно chain с более ранними багами FortiWeb.",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_25_202558034}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Authenticated RCE; likely chained with earlier FortiWeb bugs.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-58034 · <strong>Product:</strong> FortiWeb · <strong>Class:</strong> OS command injection</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>WAF appliances with command injection invert the security model — the protector becomes the payload runner.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Authenticated RCE; вероятно chain с более ранними багами FortiWeb.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-58034 · <strong>Продукт:</strong> FortiWeb · <strong>Класс:</strong> OS command injection</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>WAF с command injection инвертирует модель: защитник становится runner’ом payload.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 26,
      "id": "zd-26",
      "cve": "CVE-2024-55591",
      "product": "FortiOS / FortiProxy",
      "cwe": "Auth bypass",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "~50k unpatched management interfaces a week after publish.",
      "summary_ru": "~50 000 непропатченных management-интерфейсов спустя неделю после публикации.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_26_202455591}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>~50k unpatched management interfaces a week after publish.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2024-55591 · <strong>Product:</strong> FortiOS / FortiProxy · <strong>Class:</strong> Auth bypass</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Internet-facing Fortinet management planes remain a mass-exploitation magnet. Patch + remove WAN management.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>~50 000 непропатченных management-интерфейсов спустя неделю после публикации.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2024-55591 · <strong>Продукт:</strong> FortiOS / FortiProxy · <strong>Класс:</strong> Auth bypass</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Internet-facing Fortinet management — магнит массовой эксплуатации. Патч + убрать WAN management.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 27,
      "id": "zd-27",
      "cve": "CVE-2026-3055",
      "product": "NetScaler ADC/Gateway (SAML IDP)",
      "cwe": "OOB memory read",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "OOB read leaks memory fragments (admin sessions) via bad request parameters; CVSS 9.3.",
      "summary_ru": "OOB read: утечка фрагментов памяти (админ-сессии) через некорректные параметры; CVSS 9.3.",
      "practice": "oob_leak",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_27_20263055}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>OOB read leaks memory fragments (admin sessions) via bad request parameters; CVSS 9.3.</p>\n<h3>Also known as</h3>\n<p>CitrixBleed-class</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-3055 · <strong>Product:</strong> NetScaler ADC/Gateway (SAML IDP) · <strong>Class:</strong> OOB memory read</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Same family of memory-disclosure issues as classic CitrixBleed: steal session tokens from appliance memory without valid login.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>OOB read: утечка фрагментов памяти (админ-сессии) через некорректные параметры; CVSS 9.3.</p>\n<h3>Также известно как</h3>\n<p>CitrixBleed-class</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-3055 · <strong>Продукт:</strong> NetScaler ADC/Gateway (SAML IDP) · <strong>Класс:</strong> OOB memory read</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Семейство memory-disclosure как классический CitrixBleed: кража session tokens из памяти appliance без логина.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 28,
      "id": "zd-28",
      "cve": "CVE-2026-8451",
      "product": "NetScaler ADC/Gateway (SAML IDP)",
      "cwe": "OOB read in XML parser",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Exploitation within 24h of disclosure; leaks session tokens and TLS key material.",
      "summary_ru": "Эксплуатация <24ч после дисклоуза; утечка session tokens и TLS-ключей.",
      "practice": "oob_leak",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_28_20268451}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Exploitation within 24h of disclosure; leaks session tokens and TLS key material.</p>\n<h3>Also known as</h3>\n<p>CitrixBleed Echo</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-8451 · <strong>Product:</strong> NetScaler ADC/Gateway (SAML IDP) · <strong>Class:</strong> OOB read in XML parser</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>XML parser OOB accelerates post-disclosure mass scanning. Assume compromise of exposed NetScaler SAML IDP if unpatched during the first days.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Эксплуатация <24ч после дисклоуза; утечка session tokens и TLS-ключей.</p>\n<h3>Также известно как</h3>\n<p>CitrixBleed Echo</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-8451 · <strong>Продукт:</strong> NetScaler ADC/Gateway (SAML IDP) · <strong>Класс:</strong> OOB read in XML parser</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>OOB в XML-парсере ускоряет mass scanning после дисклоуза. Unpatched NetScaler SAML IDP в первые дни — assume compromise.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 29,
      "id": "zd-29",
      "cve": "CVE-2026-13474",
      "product": "NetScaler ADC/Gateway",
      "cwe": "DoS",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "DoS found by watchTowr using OpenAI Codex; same patch round as #28.",
      "summary_ru": "DoS от watchTowr (OpenAI Codex); тот же патч-раунд, что #28.",
      "practice": "dos",
      "owasp_note": "—",
      "flag": "FLAG{zd_29_202613474}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>DoS found by watchTowr using OpenAI Codex; same patch round as #28.</p>\n<h3>Also known as</h3>\n<p>HTTP/2 Bomb</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-13474 · <strong>Product:</strong> NetScaler ADC/Gateway · <strong>Class:</strong> DoS</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Resource exhaustion against ADC/Gateway can drop VPN/auth for the enterprise. Availability issues enable secondary social engineering.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>DoS от watchTowr (OpenAI Codex); тот же патч-раунд, что #28.</p>\n<h3>Также известно как</h3>\n<p>HTTP/2 Bomb</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-13474 · <strong>Продукт:</strong> NetScaler ADC/Gateway · <strong>Класс:</strong> DoS</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Исчерпание ресурсов ADC/Gateway роняет VPN/auth предприятия. Availability → вторичная social engineering.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 30,
      "id": "zd-30",
      "cve": "CVE-2026-0257",
      "product": "PAN-OS GlobalProtect",
      "cwe": "Actively exploited",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Exploitation started 4 days after patch; KEV since 29 May 2026.",
      "summary_ru": "Эксплуатация через 4 дня после патча; KEV с 29 мая 2026.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_30_20260257}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Exploitation started 4 days after patch; KEV since 29 May 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-0257 · <strong>Product:</strong> PAN-OS GlobalProtect · <strong>Class:</strong> Actively exploited</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>GlobalProtect is internet-facing by design. KEV + short patch-to-exploit window demands emergency PAN-OS upgrades and interface hardening.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Эксплуатация через 4 дня после патча; KEV с 29 мая 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-0257 · <strong>Продукт:</strong> PAN-OS GlobalProtect · <strong>Класс:</strong> Actively exploited</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>GlobalProtect по дизайну internet-facing. KEV + короткое окно patch→exploit = emergency upgrade PAN-OS и hardening интерфейсов.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 31,
      "id": "zd-31",
      "cve": "CVE-2026-0227",
      "product": "PAN-OS GlobalProtect",
      "cwe": "Improper exceptional conditions check",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Unauth DoS can push firewall into maintenance mode.",
      "summary_ru": "Unauth DoS может перевести firewall в maintenance mode.",
      "practice": "dos",
      "owasp_note": "—",
      "flag": "FLAG{zd_31_20260227}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Unauth DoS can push firewall into maintenance mode.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-0227 · <strong>Product:</strong> PAN-OS GlobalProtect · <strong>Class:</strong> Improper exceptional conditions check</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Fail-open/maintenance transitions on firewalls are operational outages and potential policy gaps during recovery.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Unauth DoS может перевести firewall в maintenance mode.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-0227 · <strong>Продукт:</strong> PAN-OS GlobalProtect · <strong>Класс:</strong> Improper exceptional conditions check</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Fail-open/maintenance на firewall — outage и возможные policy gaps на recovery.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 32,
      "id": "zd-32",
      "cve": "CVE-2025-23006",
      "product": "SonicWall SMA1000",
      "cwe": "Deserialization / unauth",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Unauth malicious code path; found by Microsoft.",
      "summary_ru": "Unauth подсадка кода; найдена Microsoft.",
      "practice": "deser",
      "owasp_note": "≈A08",
      "flag": "FLAG{zd_32_202523006}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Unauth malicious code path; found by Microsoft.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-23006 · <strong>Product:</strong> SonicWall SMA1000 · <strong>Class:</strong> Deserialization / unauth</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A08: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>SMA SSL-VPN appliances are high-value initial access. Unauth deserialization is classic appliance RCE class.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Unauth подсадка кода; найдена Microsoft.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-23006 · <strong>Продукт:</strong> SonicWall SMA1000 · <strong>Класс:</strong> Deserialization / unauth</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A08: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>SMA SSL-VPN — high-value initial access. Unauth deserialization — классика appliance RCE.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 33,
      "id": "zd-33",
      "cve": "CVE-2026-20127",
      "product": "Cisco Catalyst SD-WAN Controller/Manager",
      "cwe": "Auth bypass",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Maximum criticality — high-priv user without authorization.",
      "summary_ru": "Максимальная критичность — high-priv пользователь без авторизации.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_33_202620127}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Maximum criticality — high-priv user without authorization.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-20127 · <strong>Product:</strong> Cisco Catalyst SD-WAN Controller/Manager · <strong>Class:</strong> Auth bypass</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>SD-WAN controllers govern wide-area connectivity. Auth bypass here is enterprise-wide compromise, not a single branch router.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Максимальная критичность — high-priv пользователь без авторизации.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-20127 · <strong>Продукт:</strong> Cisco Catalyst SD-WAN Controller/Manager · <strong>Класс:</strong> Auth bypass</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>SD-WAN controllers управляют WAN. Auth bypass = enterprise-wide компромисс, не один branch router.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 34,
      "id": "zd-34",
      "cve": "CVE-2026-20122",
      "product": "Cisco SD-WAN Manager",
      "cwe": "Incorrect use of privileged APIs",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Privileged API misuse on SD-WAN Manager.",
      "summary_ru": "Некорректное использование privileged APIs в SD-WAN Manager.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_34_202620122}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Privileged API misuse on SD-WAN Manager.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-20122 · <strong>Product:</strong> Cisco SD-WAN Manager · <strong>Class:</strong> Incorrect use of privileged APIs</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Incorrect privileged API use breaks intended authz models — treat as critical management-plane bug.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Некорректное использование privileged APIs в SD-WAN Manager.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-20122 · <strong>Продукт:</strong> Cisco SD-WAN Manager · <strong>Класс:</strong> Incorrect use of privileged APIs</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Неверные privileged API ломают authz-модель management plane.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 35,
      "id": "zd-35",
      "cve": "CVE-2026-20128",
      "product": "Cisco SD-WAN Manager",
      "cwe": "Cleartext/recoverable password storage",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Cleartext or recoverable password storage.",
      "summary_ru": "Cleartext / recoverable хранение паролей.",
      "practice": "info_leak",
      "owasp_note": "≈A02",
      "flag": "FLAG{zd_35_202620128}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Cleartext or recoverable password storage.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-20128 · <strong>Product:</strong> Cisco SD-WAN Manager · <strong>Class:</strong> Cleartext/recoverable password storage</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A02: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Stored recoverable secrets on controllers enable lateral movement after any admin-file read or backup theft.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Cleartext / recoverable хранение паролей.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-20128 · <strong>Продукт:</strong> Cisco SD-WAN Manager · <strong>Класс:</strong> Cleartext/recoverable password storage</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A02: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Recoverable secrets на controllers → lateral movement после чтения admin-файлов/бэкапов.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 36,
      "id": "zd-36",
      "cve": "CVE-2025-20352",
      "product": "Cisco IOS / IOS XE (SNMP)",
      "cwe": "Stack buffer overflow",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "DoS with low priv; root RCE with admin via crafted SNMP.",
      "summary_ru": "DoS с низкими правами; RCE root с admin через crafted SNMP.",
      "practice": "cmdi",
      "owasp_note": "—",
      "flag": "FLAG{zd_36_202520352}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>DoS with low priv; root RCE with admin via crafted SNMP.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-20352 · <strong>Product:</strong> Cisco IOS / IOS XE (SNMP) · <strong>Class:</strong> Stack buffer overflow</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>SNMP remains a dangerous management protocol when exposed. Overflow → DoS or root depending on privileges.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>DoS с низкими правами; RCE root с admin через crafted SNMP.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-20352 · <strong>Продукт:</strong> Cisco IOS / IOS XE (SNMP) · <strong>Класс:</strong> Stack buffer overflow</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>SNMP опасен при exposure. Overflow → DoS или root в зависимости от привилегий.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 37,
      "id": "zd-37",
      "cve": "CVE-2023-20198",
      "product": "Cisco IOS XE Web UI",
      "cwe": "Privilege escalation / unauth account",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Textbook case: create privilege-15 account without auth; tens of thousands of devices compromised in days.",
      "summary_ru": "Хрестоматия: создание privilege-15 без auth; десятки тысяч устройств за дни.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_37_202320198}",
      "points": 15,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Textbook case: create privilege-15 account without auth; tens of thousands of devices compromised in days.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2023-20198 · <strong>Product:</strong> Cisco IOS XE Web UI · <strong>Class:</strong> Privilege escalation / unauth account</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Historic mass exploitation of IOS XE Web UI. Still a teaching case for why management UIs must not face the internet.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Хрестоматия: создание privilege-15 без auth; десятки тысяч устройств за дни.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2023-20198 · <strong>Продукт:</strong> Cisco IOS XE Web UI · <strong>Класс:</strong> Privilege escalation / unauth account</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Историческая массовая эксплуатация IOS XE Web UI. Учебный кейс: management UI не должен смотреть в интернет.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 38,
      "id": "zd-38",
      "cve": "CVE-2026-34908",
      "product": "Ubiquiti UniFi OS",
      "cwe": "Access control / path trav / input validation",
      "category": "iot",
      "category_en": "Network / IoT",
      "category_ru": "Сеть / IoT",
      "summary_en": "Related KEV trio CVE-2026-34908/34909/34910 (June 2026).",
      "summary_ru": "Связанное трио KEV CVE-2026-34908/34909/34910 (июнь 2026).",
      "practice": "path_trav",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_38_202634908}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Related KEV trio CVE-2026-34908/34909/34910 (June 2026).</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-34908 · <strong>Product:</strong> Ubiquiti UniFi OS · <strong>Class:</strong> Access control / path trav / input validation</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>UniFi OS KEV cluster combines access control, path traversal and input validation failures on widely deployed network gear.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Связанное трио KEV CVE-2026-34908/34909/34910 (июнь 2026).</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-34908 · <strong>Продукт:</strong> Ubiquiti UniFi OS · <strong>Класс:</strong> Access control / path trav / input validation</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Кластер KEV UniFi OS: access control, path traversal и input validation на массовом network gear.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 39,
      "id": "zd-39",
      "cve": "CVE-2025-67038",
      "product": "Lantronix EDS5000",
      "cwe": "Code injection",
      "category": "iot",
      "category_en": "Network / IoT",
      "category_ru": "Сеть / IoT",
      "summary_en": "Code injection; CISA KEV.",
      "summary_ru": "Code injection; CISA KEV.",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_39_202567038}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Code injection; CISA KEV.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-67038 · <strong>Product:</strong> Lantronix EDS5000 · <strong>Class:</strong> Code injection</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Industrial/serial device servers with code injection become pivot points into OT-adjacent networks.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Code injection; CISA KEV.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-67038 · <strong>Продукт:</strong> Lantronix EDS5000 · <strong>Класс:</strong> Code injection</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Industrial/serial device servers с code injection — pivot в OT-adjacent сети.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 40,
      "id": "zd-40",
      "cve": "CVE-2025-29635",
      "product": "D-Link DIR-823X",
      "cwe": "OS command injection",
      "category": "iot",
      "category_en": "Network / IoT",
      "category_ru": "Сеть / IoT",
      "summary_en": "Routers recruited into Mirai; D-Link will not patch (EoL).",
      "summary_ru": "Роутеры в Mirai; D-Link патч не выпустит (EoL).",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_40_202529635}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Routers recruited into Mirai; D-Link will not patch (EoL).</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-29635 · <strong>Product:</strong> D-Link DIR-823X · <strong>Class:</strong> OS command injection</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>EoL devices with RCE become permanent botnet nodes. Replace hardware; block WAN management forever.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Роутеры в Mirai; D-Link патч не выпустит (EoL).</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-29635 · <strong>Продукт:</strong> D-Link DIR-823X · <strong>Класс:</strong> OS command injection</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>EoL с RCE = вечные botnet nodes. Замена железа; WAN management закрыть навсегда.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 41,
      "id": "zd-41",
      "cve": "CVE-2026-22719",
      "product": "VMware Aria Operations",
      "cwe": "Command injection",
      "category": "virt",
      "category_en": "Virtualization",
      "category_ru": "Виртуализация",
      "summary_en": "Unauth RCE during support-assisted migration; KEV.",
      "summary_ru": "Unauth RCE во время support-assisted migration; KEV.",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_41_202622719}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Unauth RCE during support-assisted migration; KEV.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-22719 · <strong>Product:</strong> VMware Aria Operations · <strong>Class:</strong> Command injection</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Management/ops platforms for vSphere estates are high-value. Unauth command injection during migration workflows is full infra risk.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Unauth RCE во время support-assisted migration; KEV.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-22719 · <strong>Продукт:</strong> VMware Aria Operations · <strong>Класс:</strong> Command injection</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Ops-платформы для vSphere — high-value. Unauth command injection в migration workflow = риск всей инфры.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 42,
      "id": "zd-42",
      "cve": "CVE-2025-61882",
      "product": "Oracle E-Business Suite",
      "cwe": "SSRF → unauth RCE",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "CVSS 9.8; mass exfil by Clop; exploit sold ~$70k before disclosure.",
      "summary_ru": "CVSS 9.8; массовая эксфильтр. Clop; эксплойт ~$70k до дисклоуза.",
      "practice": "ssrf_rce",
      "owasp_note": "≈A01/A10",
      "flag": "FLAG{zd_42_202561882}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CVSS 9.8; mass exfil by Clop; exploit sold ~$70k before disclosure.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-61882 · <strong>Product:</strong> Oracle E-Business Suite · <strong>Class:</strong> SSRF → unauth RCE</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01/A10: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>SSRF escalated to unauth RCE in EBS. Classic big-game ransomware/extortion against ERP. Conceptual web overlap exists, but the product is a monolithic enterprise suite with proprietary surfaces — still catalogued here as KEV-class ERP reality.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>CVSS 9.8; массовая эксфильтр. Clop; эксплойт ~$70k до дисклоуза.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-61882 · <strong>Продукт:</strong> Oracle E-Business Suite · <strong>Класс:</strong> SSRF → unauth RCE</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01/A10: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>SSRF → unauth RCE в EBS. Классика big-game ransomware/extortion против ERP. Есть концептуальный веб-overlap, но продукт — монолитный enterprise suite; в каталоге как KEV-реальность ERP.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 43,
      "id": "zd-43",
      "cve": "CVE-2026-35273",
      "product": "Oracle PeopleSoft PeopleTools",
      "cwe": "Missing authentication",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "Used as zero-day by ShinyHunters.",
      "summary_ru": "Использована ShinyHunters как zero-day.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_43_202635273}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Used as zero-day by ShinyHunters.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-35273 · <strong>Product:</strong> Oracle PeopleSoft PeopleTools · <strong>Class:</strong> Missing authentication</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Missing authentication on critical PeopleTools functions → data theft / extortion against HR/finance systems.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Использована ShinyHunters как zero-day.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-35273 · <strong>Продукт:</strong> Oracle PeopleSoft PeopleTools · <strong>Класс:</strong> Missing authentication</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Missing auth на critical PeopleTools functions → кража/extortion HR/finance систем.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 44,
      "id": "zd-44",
      "cve": "CVE-2026-45659",
      "product": "Microsoft SharePoint Server",
      "cwe": "Deserialization of untrusted data",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "Deserialization; CISA KEV July 2026.",
      "summary_ru": "Deserialization; CISA KEV, июль 2026.",
      "practice": "deser",
      "owasp_note": "≈A08",
      "flag": "FLAG{zd_44_202645659}",
      "points": 15,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Deserialization; CISA KEV July 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-45659 · <strong>Product:</strong> Microsoft SharePoint Server · <strong>Class:</strong> Deserialization of untrusted data</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A08: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>On-prem SharePoint deserialization remains a staple of enterprise breach reports. KEV listing means active campaigns.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Deserialization; CISA KEV, июль 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-45659 · <strong>Продукт:</strong> Microsoft SharePoint Server · <strong>Класс:</strong> Deserialization of untrusted data</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A08: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>On-prem SharePoint deserialization — классика enterprise breach. KEV = активные кампании.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 45,
      "id": "zd-45",
      "cve": "CVE-2026-21509",
      "product": "Microsoft Office",
      "cwe": "OLE mitigation bypass",
      "category": "client",
      "category_en": "Client utilities",
      "category_ru": "Клиентские утилиты",
      "summary_en": "Out-of-band Jan 2026 patch; APT28 Operation Neusploit — RTF with MiniDoor/PixyNetLoader/Covenant Grunt.",
      "summary_ru": "Внеплановый патч янв 2026; APT28 Neusploit — RTF с MiniDoor/PixyNetLoader/Covenant Grunt.",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{zd_45_202621509}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Out-of-band Jan 2026 patch; APT28 Operation Neusploit — RTF with MiniDoor/PixyNetLoader/Covenant Grunt.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-21509 · <strong>Product:</strong> Microsoft Office · <strong>Class:</strong> OLE mitigation bypass</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Document-borne espionage: OLE bypass lets malicious RTF/Office paths execute loaders. Patch Office fully; block macros/OLE where policy allows.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Внеплановый патч янв 2026; APT28 Neusploit — RTF с MiniDoor/PixyNetLoader/Covenant Grunt.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-21509 · <strong>Продукт:</strong> Microsoft Office · <strong>Класс:</strong> OLE mitigation bypass</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Document-borne espionage: OLE bypass → RTF/Office loaders. Полный патч Office; блок macros/OLE по политике.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 46,
      "id": "zd-46",
      "cve": "CVE-2026-20253",
      "product": "Splunk Enterprise",
      "cwe": "Missing authentication",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "Missing authentication for critical function; KEV.",
      "summary_ru": "Missing authentication for critical function; KEV.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_46_202620253}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Missing authentication for critical function; KEV.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-20253 · <strong>Product:</strong> Splunk Enterprise · <strong>Class:</strong> Missing authentication</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>SIEM/analytics platforms with missing auth become both intel goldmines and deletion points for attackers covering tracks.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Missing authentication for critical function; KEV.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-20253 · <strong>Продукт:</strong> Splunk Enterprise · <strong>Класс:</strong> Missing authentication</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>SIEM/analytics без auth — золото разведки и точка зачистки следов для атакующих.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 47,
      "id": "zd-47",
      "cve": "CVE-2025-8088",
      "product": "WinRAR (Windows)",
      "cwe": "Path traversal via NTFS ADS",
      "category": "client",
      "category_en": "Client utilities",
      "category_ru": "Клиентские утилиты",
      "summary_en": "Files planted into Startup via ADS; RomCom/Sandworm/Turla since July 2025; still exploited June 2026 (no auto-update).",
      "summary_ru": "Подкладка в Startup через ADS; RomCom/Sandworm/Turla с июля 2025; эксплуатация и в июне 2026 (нет автообновления).",
      "practice": "path_trav",
      "owasp_note": "—",
      "flag": "FLAG{zd_47_20258088}",
      "points": 15,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Files planted into Startup via ADS; RomCom/Sandworm/Turla since July 2025; still exploited June 2026 (no auto-update).</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-8088 · <strong>Product:</strong> WinRAR (Windows) · <strong>Class:</strong> Path traversal via NTFS ADS</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>WinRAR does not auto-update. Path traversal via NTFS Alternate Data Streams drops payloads into persistence locations when users extract archives.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Подкладка в Startup через ADS; RomCom/Sandworm/Turla с июля 2025; эксплуатация и в июне 2026 (нет автообновления).</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-8088 · <strong>Продукт:</strong> WinRAR (Windows) · <strong>Класс:</strong> Path traversal via NTFS ADS</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>У WinRAR нет автообновления. Path traversal через NTFS ADS кладёт payload в persistence при распаковке архивов.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 48,
      "id": "zd-48",
      "cve": "CVE-2025-6218",
      "product": "WinRAR (Windows)",
      "cwe": "Path traversal",
      "category": "client",
      "category_en": "Client utilities",
      "category_ru": "Клиентские утилиты",
      "summary_en": "Used with #47 by Paper Werewolf.",
      "summary_ru": "Использовалась вместе с #47 группой Paper Werewolf.",
      "practice": "path_trav",
      "owasp_note": "—",
      "flag": "FLAG{zd_48_20256218}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Used with #47 by Paper Werewolf.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-6218 · <strong>Product:</strong> WinRAR (Windows) · <strong>Class:</strong> Path traversal</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Second WinRAR traversal in the same threat ecosystem — patch to latest WinRAR build mandatory.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Использовалась вместе с #47 группой Paper Werewolf.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-6218 · <strong>Продукт:</strong> WinRAR (Windows) · <strong>Класс:</strong> Path traversal</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Второй path traversal WinRAR в той же threat ecosystem — обязателен latest build.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 49,
      "id": "zd-49",
      "cve": "CVE-2025-55188",
      "product": "7-Zip",
      "cwe": "Unsafe symlink extraction",
      "category": "client",
      "category_en": "Client utilities",
      "category_ru": "Клиентские утилиты",
      "summary_en": "Arbitrary file write via crafted archive; most reliable on Linux.",
      "summary_ru": "Произвольная запись через crafted-архив; надёжнее всего на Linux.",
      "practice": "symlink",
      "owasp_note": "—",
      "flag": "FLAG{zd_49_202555188}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Arbitrary file write via crafted archive; most reliable on Linux.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2025-55188 · <strong>Product:</strong> 7-Zip · <strong>Class:</strong> Unsafe symlink extraction</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Symlink following during extract writes outside the intended directory — overwrite SSH keys, cron, configs.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Произвольная запись через crafted-архив; надёжнее всего на Linux.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2025-55188 · <strong>Продукт:</strong> 7-Zip · <strong>Класс:</strong> Unsafe symlink extraction</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Symlink при extract пишет вне целевой директории — overwrite SSH keys, cron, configs.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 50,
      "id": "zd-50",
      "cve": "CVE-2026-41940",
      "product": "cPanel & WHM",
      "cwe": "CRLF injection in cpsrvd",
      "category": "hosting",
      "category_en": "Hosting infrastructure",
      "category_ru": "Хостинг-инфраструктура",
      "summary_en": "Root via pre-auth session-file injection; ~1.5M potential instances; “Sorry” ransomware + Mirai; backup wiping.",
      "summary_ru": "Root через injection в pre-auth session-файл; ~1.5 млн инстансов; ransomware «Sorry» + Mirai; wiping бэкапов.",
      "practice": "crlf",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_50_202641940}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Root via pre-auth session-file injection; ~1.5M potential instances; “Sorry” ransomware + Mirai; backup wiping.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-41940 · <strong>Product:</strong> cPanel & WHM · <strong>Class:</strong> CRLF injection in cpsrvd</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>CRLF into cpsrvd session handling forges privileged session state before auth. Hosting panels at internet scale are mass ransomware targets.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Root через injection в pre-auth session-файл; ~1.5 млн инстансов; ransomware «Sorry» + Mirai; wiping бэкапов.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-41940 · <strong>Продукт:</strong> cPanel & WHM · <strong>Класс:</strong> CRLF injection in cpsrvd</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>CRLF в session handling cpsrvd куёт privileged session state до auth. Хостинг-панели на internet scale — цели массового ransomware.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 51,
      "id": "zd-51",
      "cve": "CVE-2026-39808",
      "product": "Fortinet FortiSandbox",
      "cwe": "OS command injection",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "Unauth RCE via crafted HTTP requests; CISA KEV July 2026.",
      "summary_ru": "Unauth RCE через crafted HTTP-запросы; CISA KEV, июль 2026.",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{zd_51_202639808}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Unauth RCE via crafted HTTP requests; CISA KEV July 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-39808 · <strong>Product:</strong> Fortinet FortiSandbox · <strong>Class:</strong> OS command injection</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>FortiSandbox is a widely deployed security appliance. Unauth command injection puts it in the same high-priority category as VPN/ADC KEVs.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Unauth RCE через crafted HTTP-запросы; CISA KEV, июль 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-39808 · <strong>Продукт:</strong> Fortinet FortiSandbox · <strong>Класс:</strong> OS command injection</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>FortiSandbox — широко распространённый security appliance. Unauth command injection ставит его в приоритет как VPN/ADC KEV.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 52,
      "id": "zd-52",
      "cve": "CVE-2026-58644",
      "product": "Microsoft SharePoint Server",
      "cwe": "Deserialization of untrusted data",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "Deserialization RCE; CISA KEV July 2026; related cluster with zd-44 (CVE-2026-45659).",
      "summary_ru": "Deserialization RCE; CISA KEV, июль 2026; кластер с zd-44 (CVE-2026-45659).",
      "practice": "deser",
      "owasp_note": "≈A08",
      "flag": "FLAG{zd_52_202658644}",
      "points": 15,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Deserialization RCE; CISA KEV July 2026; related cluster with zd-44 (CVE-2026-45659).</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-58644 · <strong>Product:</strong> Microsoft SharePoint Server · <strong>Class:</strong> Deserialization of untrusted data</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A08: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Second SharePoint deserialization KEV in the same period. Indicates sustained attacker focus on SharePoint as an initial access vector.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Deserialization RCE; CISA KEV, июль 2026; кластер с zd-44 (CVE-2026-45659).</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-58644 · <strong>Продукт:</strong> Microsoft SharePoint Server · <strong>Класс:</strong> Deserialization of untrusted data</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A08: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Второй SharePoint deserialization KEV за период. Устойчивый фокус атакующих на SharePoint как initial access.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 53,
      "id": "zd-53",
      "cve": "CVE-2026-46817",
      "product": "Oracle E-Business Suite (Payments)",
      "cwe": "Improper privilege management",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "Unauth takeover of Oracle Payments; CISA KEV July 2026.",
      "summary_ru": "Unauth захват Oracle Payments; CISA KEV, июль 2026.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_53_202646817}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>Unauth takeover of Oracle Payments; CISA KEV July 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-46817 · <strong>Product:</strong> Oracle E-Business Suite (Payments) · <strong>Class:</strong> Improper privilege management</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Oracle EBS is a core ERP for thousands of orgs. Privilege management flaw exposes payment module to unauthenticated takeover — financial fraud risk.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Unauth захват Oracle Payments; CISA KEV, июль 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-46817 · <strong>Продукт:</strong> Oracle E-Business Suite (Payments) · <strong>Класс:</strong> Improper privilege management</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Oracle EBS — core ERP тысяч организаций. Flaw в управлении привилегиями открывает payment module для unauth takeover — риск финансового мошенничества.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 54,
      "id": "zd-54",
      "cve": "CVE-2026-48558",
      "product": "SimpleHelp",
      "cwe": "Authentication bypass via OIDC",
      "category": "client",
      "category_en": "Client utilities",
      "category_ru": "Клиентские утилиты",
      "summary_en": "OIDC identity tokens accepted without signature verification; unauth technician session; CISA KEV June 2026.",
      "summary_ru": "OIDC-токены без проверки подписи; unauth technician session; CISA KEV, июнь 2026.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_54_202648558}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>OIDC identity tokens accepted without signature verification; unauth technician session; CISA KEV June 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-48558 · <strong>Product:</strong> SimpleHelp · <strong>Class:</strong> Authentication bypass via OIDC</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>Remote support tools are high-value targets. OIDC token forgery bypasses MFA and grants full remote control — used in ransomware deployment.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>OIDC-токены без проверки подписи; unauth technician session; CISA KEV, июнь 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-48558 · <strong>Продукт:</strong> SimpleHelp · <strong>Класс:</strong> Authentication bypass via OIDC</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Remote support tools — high-value цели. OIDC token forgery обходит MFA и даёт полный remote control — используется в ransomware.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 55,
      "id": "zd-55",
      "cve": "CVE-2026-48282",
      "product": "Adobe ColdFusion",
      "cwe": "Path traversal",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "Path traversal → arbitrary code execution; CISA KEV July 2026.",
      "summary_ru": "Path traversal → произвольный код; CISA KEV, июль 2026.",
      "practice": "path_trav",
      "owasp_note": "≈A01",
      "flag": "FLAG{zd_55_202648282}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\n<p>Path traversal → arbitrary code execution; CISA KEV July 2026.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-48282 · <strong>Product:</strong> Adobe ColdFusion · <strong>Class:</strong> Path traversal</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\n<h3>Conceptual OWASP overlap</h3>\n<p>Marked ≈A01: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\n<h3>What happened / why it matters</h3>\n<p>ColdFusion remains a legacy enterprise platform with recurring path traversal bugs. KEV listing signals active scanning and exploitation.</p>\n<h3>Attack narrative</h3>\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li><li>Trigger the vulnerability class listed above</li><li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li><li>Isolate management planes; disable unused services</li><li>EDR / memory integrity / least privilege</li><li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources (catalog period)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\n<p>Path traversal → произвольный код; CISA KEV, июль 2026.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-48282 · <strong>Продукт:</strong> Adobe ColdFusion · <strong>Класс:</strong> Path traversal</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\n<h3>Концептуальное пересечение с OWASP</h3>\n<p>Метка ≈A01: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\n<h3>Что произошло / почему важно</h3>\n<p>ColdFusion — legacy enterprise platform с recurring path traversal. KEV = активное сканирование и эксплуатация.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Получить foothold (local user, unauth edge, документ, crafted page)</li><li>Триггернуть уязвимость указанного класса</li><li>LPE, RCE, кража сессий, ботнет или ransomware — как в кампаниях KEV 2025–2026</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Патч ASAP; CISA KEV и vendor advisories</li><li>Изоляция management plane; отключить лишние сервисы</li><li>EDR / memory integrity / least privilege</li><li>Инвентаризация internet-facing appliance (VPN/MDM/ADC)</li></ul>\n<h3>Источники (период каталога)</h3>\n<p>CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (конец 2025 — июль 2026).</p>"
    },
    {
      "n": 56,
      "id": "zd-56",
      "cve": "CVE-2026-16095",
      "product": "Shibby Tomato",
      "cwe": "CWE-119 / CWE-787",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "High (CVSS 9) — Shibby Tomato version 1.28 RT-N5x MIPSR2 Build 124 A remote out-of-bounds write can occur due to a flaw in the `setup conntrack()` function within the `/sbin/rc` file",
      "summary_ru": "High (CVSS 9) — Shibby Tomato versão 1.28 RT-N5x MIPSR2 Build 124 Uma gravação fora dos limites (out-of-bounds write) remota pode ocorrer devido a uma falha na função `setup conntrack()` dentro do arquivo `/sbin/rc`",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{202616095}",
      "points": 12,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\\n<p>Shibby Tomato version 1.28 RT-N5x MIPSR2 Build 124 A remote out-of-bounds write can occur due to a flaw in the `setup conntrack()` function within the `/sbin/rc` file</p>\\n<h3>Product & class</h3>\\n<p><strong>CVE:</strong> CVE-2026-16095 · <strong>Product:</strong> Shibby Tomato · <strong>Class:</strong> CWE-119 / CWE-787</p>\\n<h3>Why outside OWASP Top 10</h3>\\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\\n<h3>Conceptual OWASP overlap</h3>\\n<p>Marked —: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\\n<h3>What happened / why it matters</h3>\\n<p>Shibby Tomato version 1.28 RT-N5x MIPSR2 Build 124 A remote out-of-bounds write can occur due to a flaw in the `setup conntrack()` function within the `/sbin/rc` file. This issue is triggered by manipulating the `ct tcp timeout` argument.</p>\\n<h3>Attack narrative</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>How defenders respond</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Sources (catalog period)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\\n<p>Shibby Tomato version 1.28 RT-N5x MIPSR2 Build 124 A remote out-of-bounds write can occur due to a flaw in the `setup conntrack()` function within the `/sbin/rc` file</p>\\n<h3>Продукт и класс</h3>\\n<p><strong>CVE:</strong> CVE-2026-16095 · <strong>Product:</strong> Shibby Tomato · <strong>Class:</strong> CWE-119 / CWE-787</p>\\n<h3>Почему вне OWASP Top 10</h3>\\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\\n<h3>Концептуальное пересечение с OWASP</h3>\\n<p>Метка —: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\\n<h3>Что произошло / почему важно</h3>\\n<p>Shibby Tomato version 1.28 RT-N5x MIPSR2 Build 124 A remote out-of-bounds write can occur due to a flaw in the `setup conntrack()` function within the `/sbin/rc` file. This issue is triggered by manipulating the `ct tcp timeout` argument.</p>\\n<h3>Нарратив атаки</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>Как защищаться</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Источники (период каталога)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>"
    },
    {
      "n": 57,
      "id": "zd-57",
      "cve": "CVE-2026-47867",
      "product": "Vmware Avi Load Balancer",
      "cwe": "CWE-94",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "High (CVSS 8.7) — VMware Avi Load Balancer versions prior to 32.1.2 VMware Avi Load Balancer versions 31.1.1 through 31.2.2 VMware Avi Load Balancer versions 30.1.1 through 30.2.6 VMware Avi Load Balancer versions 22.1",
      "summary_ru": "High (CVSS 8.7) — VMware Avi Load Balancer versões anteriores a 32.1.2 VMware Avi Load Balancer versões 31.1.1 até 31.2.2 VMware Avi Load Balancer versões 30.1.1 até 30.2.6 VMware Avi Load Balancer versões 22.1.1 até 2",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{202647867}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\\n<p>VMware Avi Load Balancer versions prior to 32.1.2 VMware Avi Load Balancer versions 31.1.1 through 31.2.2 VMware Avi Load Balancer versions 30.1.1 through 30.2.6 VMware Avi Load Balancer versions 22.1 Fix available.</p>\\n<h3>Product & class</h3>\\n<p><strong>CVE:</strong> CVE-2026-47867 · <strong>Product:</strong> Avi Load Balancer · <strong>Class:</strong> CWE-94</p>\\n<h3>Why outside OWASP Top 10</h3>\\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\\n<h3>Conceptual OWASP overlap</h3>\\n<p>Marked ≈A05: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\\n<h3>What happened / why it matters</h3>\\n<p>VMware Avi Load Balancer versions prior to 32.1.2 VMware Avi Load Balancer versions 31.1.1 through 31.2.2 VMware Avi Load Balancer versions 30.1.1 through 30.2.6 VMware Avi Load Balancer versions 22.1.1 through 22.1.7 A remote code execution issue exists where a malicious user with network access can access the Avi Control plane to execute arbitrary code remotely.1.2.2.2-2p3.2.7.2.7.</p>\\n<h3>Attack narrative</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>How defenders respond</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Sources (catalog period)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\\n<p>VMware Avi Load Balancer versions prior to 32.1.2 VMware Avi Load Balancer versions 31.1.1 through 31.2.2 VMware Avi Load Balancer versions 30.1.1 through 30.2.6 VMware Avi Load Balancer versions 22.1 Fix available.</p>\\n<h3>Продукт и класс</h3>\\n<p><strong>CVE:</strong> CVE-2026-47867 · <strong>Product:</strong> Avi Load Balancer · <strong>Class:</strong> CWE-94</p>\\n<h3>Почему вне OWASP Top 10</h3>\\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\\n<h3>Концептуальное пересечение с OWASP</h3>\\n<p>Метка ≈A05: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\\n<h3>Что произошло / почему важно</h3>\\n<p>VMware Avi Load Balancer versions prior to 32.1.2 VMware Avi Load Balancer versions 31.1.1 through 31.2.2 VMware Avi Load Balancer versions 30.1.1 through 30.2.6 VMware Avi Load Balancer versions 22.1.1 through 22.1.7 A remote code execution issue exists where a malicious user with network access can access the Avi Control plane to execute arbitrary code remotely.1.2.2.2-2p3.2.7.2.7.</p>\\n<h3>Нарратив атаки</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>Как защищаться</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Источники (период каталога)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>"
    },
    {
      "n": 58,
      "id": "zd-58",
      "cve": "CVE-2024-58366",
      "product": "Surrealdb",
      "cwe": "CWE-134",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "High (CVSS 8.5) — SurrealDB before 1.1.1 contains a format string vulnerability in the rquickjs Exception::throw type function when scripting is enabled",
      "summary_ru": "High (CVSS 8.5) — SurrealDB before 1.1.1 contains a format string vulnerability in the rquickjs Exception::throw type function when scripting is enabled",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{202458366}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\\n<p>SurrealDB before 1.1.1 contains a format string vulnerability in the rquickjs Exception::throw type function when scripting is enabled Fix available.</p>\\n<h3>Product & class</h3>\\n<p><strong>CVE:</strong> CVE-2024-58366 · <strong>Product:</strong> Surrealdb · <strong>Class:</strong> CWE-134</p>\\n<h3>Why outside OWASP Top 10</h3>\\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\\n<h3>Conceptual OWASP overlap</h3>\\n<p>Marked —: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\\n<h3>What happened / why it matters</h3>\\n<p>SurrealDB before 1.1.1 contains a format string vulnerability in the rquickjs Exception::throw type function when scripting is enabled. Attackers with scripting privileges can supply format string sequences in error inputs to read arbitrary memory or execute code with SurrealDB process privileges.</p>\\n<h3>Attack narrative</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>How defenders respond</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Sources (catalog period)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\\n<p>SurrealDB before 1.1.1 contains a format string vulnerability in the rquickjs Exception::throw type function when scripting is enabled Fix available.</p>\\n<h3>Продукт и класс</h3>\\n<p><strong>CVE:</strong> CVE-2024-58366 · <strong>Product:</strong> Surrealdb · <strong>Class:</strong> CWE-134</p>\\n<h3>Почему вне OWASP Top 10</h3>\\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\\n<h3>Концептуальное пересечение с OWASP</h3>\\n<p>Метка —: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\\n<h3>Что произошло / почему важно</h3>\\n<p>SurrealDB before 1.1.1 contains a format string vulnerability in the rquickjs Exception::throw type function when scripting is enabled. Attackers with scripting privileges can supply format string sequences in error inputs to read arbitrary memory or execute code with SurrealDB process privileges.</p>\\n<h3>Нарратив атаки</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>Как защищаться</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Источники (период каталога)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>"
    },
    {
      "n": 59,
      "id": "zd-59",
      "cve": "CVE-2026-16117",
      "product": "@Fastify/Http Proxy Fastify-Http-Proxy",
      "cwe": "CWE-20",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "Critical (CVSS 10) — Impact: @fastify/http-proxy versions up to and including 11.5.0 fail to rewrite the request prefix when the prefix segment is URL-encoded",
      "summary_ru": "Critical (CVSS 10) — Impact: @fastify/http-proxy versions up to and including 11.5.0 fail to rewrite the request prefix when the prefix segment is URL-encoded",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{202616117}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\\n<p>Impact: @fastify/http-proxy versions up to and including 11.5.0 fail to rewrite the request prefix when the prefix segment is URL-encoded Fix available.</p>\\n<h3>Product & class</h3>\\n<p><strong>CVE:</strong> CVE-2026-16117 · <strong>Product:</strong> Fastify-Http-Proxy · <strong>Class:</strong> CWE-20</p>\\n<h3>Why outside OWASP Top 10</h3>\\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\\n<h3>Conceptual OWASP overlap</h3>\\n<p>Marked —: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\\n<h3>What happened / why it matters</h3>\\n<p>Impact: @fastify/http-proxy versions up to and including 11.5.0 fail to rewrite the request prefix when the prefix segment is URL-encoded. Fastify's router URL-decodes paths for route matching, but request.url retains the original encoded form, and the prefix-rewrite step uses a literal string replace against the decoded prefix. A request that encodes one or more characters of the configured prefix therefore matches the route but skips the rewrite, so the raw encoded path is forwarded to the upstream unchanged. The upstream then decodes the path and serves it, letting an attacker reach upstrea...</p>\\n<h3>Attack narrative</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>How defenders respond</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Sources (catalog period)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\\n<p>Impact: @fastify/http-proxy versions up to and including 11.5.0 fail to rewrite the request prefix when the prefix segment is URL-encoded Fix available.</p>\\n<h3>Продукт и класс</h3>\\n<p><strong>CVE:</strong> CVE-2026-16117 · <strong>Product:</strong> Fastify-Http-Proxy · <strong>Class:</strong> CWE-20</p>\\n<h3>Почему вне OWASP Top 10</h3>\\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\\n<h3>Концептуальное пересечение с OWASP</h3>\\n<p>Метка —: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\\n<h3>Что произошло / почему важно</h3>\\n<p>Impact: @fastify/http-proxy versions up to and including 11.5.0 fail to rewrite the request prefix when the prefix segment is URL-encoded. Fastify's router URL-decodes paths for route matching, but request.url retains the original encoded form, and the prefix-rewrite step uses a literal string replace against the decoded prefix. A request that encodes one or more characters of the configured prefix therefore matches the route but skips the rewrite, so the raw encoded path is forwarded to the upstream unchanged. The upstream then decodes the path and serves it, letting an attacker reach upstrea...</p>\\n<h3>Нарратив атаки</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>Как защищаться</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Источники (период каталога)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>"
    },
    {
      "n": 60,
      "id": "zd-60",
      "cve": "CVE-2024-58362",
      "product": "Surrealdb",
      "cwe": "CWE-75",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "High (CVSS 8.8) — SurrealDB before 1.5.5 (and 2.0.0-beta before 2.0.0-beta.3) accepts an arbitrary object in the signin and signup operations of the RPC API without recursively validating it for non-computed values",
      "summary_ru": "High (CVSS 8.8) — SurrealDB before 1.5.5 (and 2.0.0-beta before 2.0.0-beta.3) accepts an arbitrary object in the signin and signup operations of the RPC API without recursively validating it for non-computed values",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{202458362}",
      "points": 12,
      "diff": 2,
      "theory_en": "<h3>What it is</h3>\\n<p>SurrealDB before 1.5.5 (and 2.0.0-beta before 2.0.0-beta.3) accepts an arbitrary object in the signin and signup operations of the RPC API without recursively validating it for non-computed values Fix available.</p>\\n<h3>Product & class</h3>\\n<p><strong>CVE:</strong> CVE-2024-58362 · <strong>Product:</strong> Surrealdb · <strong>Class:</strong> CWE-75</p>\\n<h3>Why outside OWASP Top 10</h3>\\n<p>OWASP Top 10 covers web-application design/code. This issue lives in OS/firmware/browser/client layers (memory safety, appliance binaries, proprietary protocols) where OWASP web controls do not apply.</p>\\n<h3>Conceptual OWASP overlap</h3>\\n<p>Marked —: similar abstract class, but exploit path is appliance/OS/client — not a typical web app stack with ORM/session middleware.</p>\\n<h3>What happened / why it matters</h3>\\n<p>SurrealDB before 1.5.5 (and 2.0.0-beta before 2.0.0-beta.3) accepts an arbitrary object in the signin and signup operations of the RPC API without recursively validating it for non-computed values. When a record access method defines a SIGNIN or SIGNUP query and the RPC API is exposed to untrusted users, an unauthenticated attacker can encode a binary object containing a subquery using the bincode serialization format and supply it in place of credentials. The subquery is then executed within the database owner's SIGNIN/SIGNUP query under a system user session with the editor role, allowing th...</p>\\n<h3>Attack narrative</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>How defenders respond</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Sources (catalog period)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>",
      "theory_ru": "<h3>Что это</h3>\\n<p>SurrealDB before 1.5.5 (and 2.0.0-beta before 2.0.0-beta.3) accepts an arbitrary object in the signin and signup operations of the RPC API without recursively validating it for non-computed values Fix available.</p>\\n<h3>Продукт и класс</h3>\\n<p><strong>CVE:</strong> CVE-2024-58362 · <strong>Product:</strong> Surrealdb · <strong>Class:</strong> CWE-75</p>\\n<h3>Почему вне OWASP Top 10</h3>\\n<p>OWASP Top 10 — таксономия веб-приложений. Эта уязвимость в ОС/firmware/браузере/клиенте (memory-safety, appliance-бинари, проприетарные протоколы), куда не дотягиваются веб-контроли OWASP.</p>\\n<h3>Концептуальное пересечение с OWASP</h3>\\n<p>Метка —: похожий абстрактный класс, но вектор — appliance/ОС/клиент, не типовой веб-стек с ORM/session middleware.</p>\\n<h3>Что произошло / почему важно</h3>\\n<p>SurrealDB before 1.5.5 (and 2.0.0-beta before 2.0.0-beta.3) accepts an arbitrary object in the signin and signup operations of the RPC API without recursively validating it for non-computed values. When a record access method defines a SIGNIN or SIGNUP query and the RPC API is exposed to untrusted users, an unauthenticated attacker can encode a binary object containing a subquery using the bincode serialization format and supply it in place of credentials. The subquery is then executed within the database owner's SIGNIN/SIGNUP query under a system user session with the editor role, allowing th...</p>\\n<h3>Нарратив атаки</h3>\\n<ul><li>Obtain appropriate foothold (local user, unauth edge, document, crafted page)</li>\\n<li>Trigger the vulnerability class listed above</li>\\n<li>Achieve LPE, RCE, session theft, botnet recruitment, or ransomware staging as seen in 2025–2026 KEV campaigns</li></ul>\\n<h3>Как защищаться</h3>\\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\\n<li>Isolate management planes; disable unused services</li>\\n<li>EDR / memory integrity / least privilege</li>\\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\\n<h3>Источники (период каталога)</h3>\\n<p>dbugs.ptsecurity.com · CISA KEV · vendor advisories · Mandiant/GTIG · Unit42 · ESET · Tenable/Rapid7 · SecurityWeek · TheHackerNews · BleepingComputer (late 2025 – July 2026).</p>"
    },
    {
      "n": 61,
      "id": "zd-61",
      "cve": "CVE-2026-25089",
      "product": "Fortinet FortiSandbox",
      "cwe": "CWE-78",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "CRITICAL (CVSS 9.8) — A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, Fo",
      "summary_ru": "CRITICAL (CVSS 9.8) — A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, Fo",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{202625089}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 9.8) — A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, Fo</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-25089 · <strong>Product:</strong> Fortinet FortiSandbox · <strong>Class:</strong> CWE-78</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, FortiSandbox Cloud 5.0.4 through 5.0.5, FortiSandbox PaaS 5.0.4 through 5.0.5 may allow an unauthenticated attacker to execute unauthorized commands via specifically crafted HTTP requests</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://fortiguard.fortinet.com/psirt/FG-IR-26-141\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 9.8) — A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, Fo</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-25089 · <strong>Product:</strong> Fortinet FortiSandbox · <strong>Class:</strong> CWE-78</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, FortiSandbox Cloud 5.0.4 through 5.0.5, FortiSandbox PaaS 5.0.4 through 5.0.5 may allow an unauthenticated attacker to execute unauthorized commands via specifically crafted HTTP requests</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://fortiguard.fortinet.com/psirt/FG-IR-26-141\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-25089\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-25089"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-25089"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-25089"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://fortiguard.fortinet.com/psirt/FG-IR-26-141"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-25089"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 62,
      "id": "zd-62",
      "cve": "CVE-2023-4346",
      "product": "KNX Association KNX Protocol Connection Authorization Option 1",
      "cwe": "CWE-645",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "HIGH (CVSS 7.5) — KNX devices that use KNX Connection Authorization and support Option 1 are, depending on the implementation, vulnerable to being locked and users being unable to reset them to gain access to the device",
      "summary_ru": "HIGH (CVSS 7.5) — KNX devices that use KNX Connection Authorization and support Option 1 are, depending on the implementation, vulnerable to being locked and users being unable to reset them to gain access to the device",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{20234346}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>HIGH (CVSS 7.5) — KNX devices that use KNX Connection Authorization and support Option 1 are, depending on the implementation, vulnerable to being locked and users being unable to reset them to gain access to the device</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2023-4346 · <strong>Product:</strong> KNX Association KNX Protocol Connection Authorization Option 1 · <strong>Class:</strong> CWE-645</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>KNX devices that use KNX Connection Authorization and support Option 1 are, depending on the implementation, vulnerable to being locked and users being unable to reset them to gain access to the device. The BCU key feature on the devices can be used to create a password for the device, but this password can often not be reset without entering the current password. If the device is configured to interface with a network, an attacker with access to that network could interface with the KNX installation, purge all devices without additional security options enabled, and set a BCU key, locking the device. Even if a device is not connected to a network, an attacker with physical access to the dev…</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>HIGH (CVSS 7.5) — KNX devices that use KNX Connection Authorization and support Option 1 are, depending on the implementation, vulnerable to being locked and users being unable to reset them to gain access to the device</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2023-4346 · <strong>Product:</strong> KNX Association KNX Protocol Connection Authorization Option 1 · <strong>Class:</strong> CWE-645</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>KNX devices that use KNX Connection Authorization and support Option 1 are, depending on the implementation, vulnerable to being locked and users being unable to reset them to gain access to the device. The BCU key feature on the devices can be used to create a password for the device, but this password can often not be reset without entering the current password. If the device is configured to interface with a network, an attacker with access to that network could interface with the KNX installation, purge all devices without additional security options enabled, and set a BCU key, locking the device. Even if a device is not connected to a network, an attacker with physical access to the dev…</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-4346\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-4346"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2023-4346"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4346"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-4346"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 63,
      "id": "zd-63",
      "cve": "CVE-2026-56155",
      "product": "Microsoft Active Directory Federation Services",
      "cwe": "CWE-1220",
      "category": "windows",
      "category_en": "Windows",
      "category_ru": "Windows",
      "summary_en": "HIGH (CVSS 7.8) — Microsoft Active Directory Federation Services contains an insufficient granularity of access control vulnerability that allows an authorized attacker to elevate privileges locally.",
      "summary_ru": "HIGH (CVSS 7.8) — Microsoft Active Directory Federation Services contains an insufficient granularity of access control vulnerability that allows an authorized attacker to elevate privileges locally.",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{202656155}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>HIGH (CVSS 7.8) — Microsoft Active Directory Federation Services contains an insufficient granularity of access control vulnerability that allows an authorized attacker to elevate privileges locally.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-56155 · <strong>Product:</strong> Microsoft Active Directory Federation Services · <strong>Class:</strong> CWE-1220</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Microsoft Active Directory Federation Services contains an insufficient granularity of access control vulnerability that allows an authorized attacker to elevate privileges locally.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/decommission/adfs-decommission-guide\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">Vendor</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>HIGH (CVSS 7.8) — Microsoft Active Directory Federation Services contains an insufficient granularity of access control vulnerability that allows an authorized attacker to elevate privileges locally.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-56155 · <strong>Product:</strong> Microsoft Active Directory Federation Services · <strong>Class:</strong> CWE-1220</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Microsoft Active Directory Federation Services contains an insufficient granularity of access control vulnerability that allows an authorized attacker to elevate privileges locally.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/decommission/adfs-decommission-guide\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">Vendor</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56155\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-56155"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-56155"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56155"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-56155"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/decommission/adfs-decommission-guide"
        },
        {
          "name": "Vendor",
          "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56155"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56155"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 64,
      "id": "zd-64",
      "cve": "CVE-2026-56164",
      "product": "Microsoft SharePoint Server",
      "cwe": "CWE-306",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "MEDIUM (CVSS 5.3) — Microsoft SharePoint contains a missing authentication for critical function vulnerability that allows an unauthorized attacker to elevate privileges over a network.",
      "summary_ru": "MEDIUM (CVSS 5.3) — Microsoft SharePoint contains a missing authentication for critical function vulnerability that allows an unauthorized attacker to elevate privileges over a network.",
      "practice": "auth_bypass",
      "owasp_note": "≈A01",
      "flag": "FLAG{202656164}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>MEDIUM (CVSS 5.3) — Microsoft SharePoint contains a missing authentication for critical function vulnerability that allows an unauthorized attacker to elevate privileges over a network.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-56164 · <strong>Product:</strong> Microsoft SharePoint Server · <strong>Class:</strong> CWE-306</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Microsoft SharePoint contains a missing authentication for critical function vulnerability that allows an unauthorized attacker to elevate privileges over a network.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">Vendor</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>MEDIUM (CVSS 5.3) — Microsoft SharePoint contains a missing authentication for critical function vulnerability that allows an unauthorized attacker to elevate privileges over a network.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-56164 · <strong>Product:</strong> Microsoft SharePoint Server · <strong>Class:</strong> CWE-306</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Microsoft SharePoint contains a missing authentication for critical function vulnerability that allows an unauthorized attacker to elevate privileges over a network.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">Vendor</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56164\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-56164"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-56164"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56164"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-56164"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Vendor",
          "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56164"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56164"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 65,
      "id": "zd-65",
      "cve": "CVE-2026-15409",
      "product": "SonicWall SMA1000 Appliances",
      "cwe": "CWE-918",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "CRITICAL (CVSS 10.0) — A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface",
      "summary_ru": "CRITICAL (CVSS 10.0) — A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface",
      "practice": "ssrf_rce",
      "owasp_note": "≈A01/A10",
      "flag": "FLAG{202615409}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 10.0) — A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-15409 · <strong>Product:</strong> SonicWall SMA1000 Appliances · <strong>Class:</strong> CWE-918</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 10.0) — A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-15409 · <strong>Product:</strong> SonicWall SMA1000 Appliances · <strong>Class:</strong> CWE-918</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>A Server-side request forgery (SSRF) vulnerability has been identified in the SMA1000 Appliance Work Place interface. A remote unauthenticated attacker could potentially cause the appliance to make requests to unintended location.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-15409\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-15409"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-15409"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15409"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-15409"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 66,
      "id": "zd-66",
      "cve": "CVE-2026-15410",
      "product": "SonicWall SMA1000 Appliances",
      "cwe": "CWE-94",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "HIGH (CVSS 7.2) — Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a re",
      "summary_ru": "HIGH (CVSS 7.2) — Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a re",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{202615410}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>HIGH (CVSS 7.2) — Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a re</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-15410 · <strong>Product:</strong> SonicWall SMA1000 Appliances · <strong>Class:</strong> CWE-94</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>HIGH (CVSS 7.2) — Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a re</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-15410 · <strong>Product:</strong> SonicWall SMA1000 Appliances · <strong>Class:</strong> CWE-94</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Post-authentication improper control of generation of code ('Code Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-15410\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-15410"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-15410"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15410"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0008"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-15410"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 67,
      "id": "zd-67",
      "cve": "CVE-2008-4128",
      "product": "Cisco IOS",
      "cwe": "CWE-352 / CWE-352",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "MEDIUM (CVSS 4.3) — Multiple cross-site request forgery (CSRF) vulnerabilities in the HTTP Administration component in Cisco IOS 12.4 on the 871 Integrated Services Router allow remote attackers to execute arbitrary commands via (1) a certa",
      "summary_ru": "MEDIUM (CVSS 4.3) — Multiple cross-site request forgery (CSRF) vulnerabilities in the HTTP Administration component in Cisco IOS 12.4 on the 871 Integrated Services Router allow remote attackers to execute arbitrary commands via (1) a certa",
      "practice": "csrf",
      "owasp_note": "—",
      "flag": "FLAG{20084128}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>MEDIUM (CVSS 4.3) — Multiple cross-site request forgery (CSRF) vulnerabilities in the HTTP Administration component in Cisco IOS 12.4 on the 871 Integrated Services Router allow remote attackers to execute arbitrary commands via (1) a certa</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2008-4128 · <strong>Product:</strong> Cisco IOS · <strong>Class:</strong> CWE-352 / CWE-352</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Multiple cross-site request forgery (CSRF) vulnerabilities in the HTTP Administration component in Cisco IOS 12.4 on the 871 Integrated Services Router allow remote attackers to execute arbitrary commands via (1) a certain \\\"show privilege\\\" command to the /level/15/exec/- URI, and (2) a certain \\\"alias exec\\\" command to the /level/15/exec/-/configure/http URI. NOTE: some of these details are obtained from third party information.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2008-4128\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2008-4128\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4128\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.cisco.com/c/en/us/obsolete/ios-nx-os-software/cisco-ios-software-releases-12-4-mainline.html\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"http://jbrownsec.blogspot.com/2008/09/cisco-0day-released.html\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"http://www.securityfocus.com/bid/31218\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://exchange.xforce.ibmcloud.com/vulnerabilities/45226\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.exploit-db.com/exploits/6476\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.exploit-db.com/exploits/6477\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>MEDIUM (CVSS 4.3) — Multiple cross-site request forgery (CSRF) vulnerabilities in the HTTP Administration component in Cisco IOS 12.4 on the 871 Integrated Services Router allow remote attackers to execute arbitrary commands via (1) a certa</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2008-4128 · <strong>Product:</strong> Cisco IOS · <strong>Class:</strong> CWE-352 / CWE-352</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Multiple cross-site request forgery (CSRF) vulnerabilities in the HTTP Administration component in Cisco IOS 12.4 on the 871 Integrated Services Router allow remote attackers to execute arbitrary commands via (1) a certain \\\"show privilege\\\" command to the /level/15/exec/- URI, and (2) a certain \\\"alias exec\\\" command to the /level/15/exec/-/configure/http URI. NOTE: some of these details are obtained from third party information.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2008-4128\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2008-4128\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4128\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.cisco.com/c/en/us/obsolete/ios-nx-os-software/cisco-ios-software-releases-12-4-mainline.html\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"http://jbrownsec.blogspot.com/2008/09/cisco-0day-released.html\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"http://www.securityfocus.com/bid/31218\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://exchange.xforce.ibmcloud.com/vulnerabilities/45226\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.exploit-db.com/exploits/6476\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.exploit-db.com/exploits/6477\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2008-4128"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2008-4128"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4128"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisco.com/c/en/us/obsolete/ios-nx-os-software/cisco-ios-software-releases-12-4-mainline.html"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "http://jbrownsec.blogspot.com/2008/09/cisco-0day-released.html"
        },
        {
          "name": "Exploit",
          "url": "http://www.securityfocus.com/bid/31218"
        },
        {
          "name": "Reference",
          "url": "https://exchange.xforce.ibmcloud.com/vulnerabilities/45226"
        },
        {
          "name": "Exploit",
          "url": "https://www.exploit-db.com/exploits/6476"
        },
        {
          "name": "Exploit",
          "url": "https://www.exploit-db.com/exploits/6477"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 68,
      "id": "zd-68",
      "cve": "CVE-2026-56291",
      "product": "Balbooa Forms",
      "cwe": "CWE-434",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "CRITICAL (CVSS 9.8) — Balbooa Forms contains an unrestricted upload of file with dangerous type vulnerability that allows an unauthenticated arbitrary file upload which could allow uploading of executable files leading to full RCE.",
      "summary_ru": "CRITICAL (CVSS 9.8) — Balbooa Forms contains an unrestricted upload of file with dangerous type vulnerability that allows an unauthenticated arbitrary file upload which could allow uploading of executable files leading to full RCE.",
      "practice": "file_upload",
      "owasp_note": "—",
      "flag": "FLAG{202656291}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 9.8) — Balbooa Forms contains an unrestricted upload of file with dangerous type vulnerability that allows an unauthenticated arbitrary file upload which could allow uploading of executable files leading to full RCE.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-56291 · <strong>Product:</strong> Balbooa Forms · <strong>Class:</strong> CWE-434</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Balbooa Forms contains an unrestricted upload of file with dangerous type vulnerability that allows an unauthenticated arbitrary file upload which could allow uploading of executable files leading to full RCE.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.balbooa.com/joomla-forms\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://mysites.guru/blog/balbooa-forms-unauthenticated-file-upload-flaw/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 9.8) — Balbooa Forms contains an unrestricted upload of file with dangerous type vulnerability that allows an unauthenticated arbitrary file upload which could allow uploading of executable files leading to full RCE.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-56291 · <strong>Product:</strong> Balbooa Forms · <strong>Class:</strong> CWE-434</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Balbooa Forms contains an unrestricted upload of file with dangerous type vulnerability that allows an unauthenticated arbitrary file upload which could allow uploading of executable files leading to full RCE.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.balbooa.com/joomla-forms\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://mysites.guru/blog/balbooa-forms-unauthenticated-file-upload-flaw/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56291\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-56291"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-56291"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56291"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.balbooa.com/joomla-forms"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Exploit",
          "url": "https://mysites.guru/blog/balbooa-forms-unauthenticated-file-upload-flaw/"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56291"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 69,
      "id": "zd-69",
      "cve": "CVE-2026-48939",
      "product": "iCagenda iCagenda",
      "cwe": "CWE-434 / CWE-434",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "CRITICAL (CVSS 9.8) — iCagenda contains an unrestricted upload of file with dangerous type vulnerability that allows the upload of arbitrary files in the file attachment feature, ultimately resulting in PHP code upload and execution.",
      "summary_ru": "CRITICAL (CVSS 9.8) — iCagenda contains an unrestricted upload of file with dangerous type vulnerability that allows the upload of arbitrary files in the file attachment feature, ultimately resulting in PHP code upload and execution.",
      "practice": "file_upload",
      "owasp_note": "—",
      "flag": "FLAG{202648939}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 9.8) — iCagenda contains an unrestricted upload of file with dangerous type vulnerability that allows the upload of arbitrary files in the file attachment feature, ultimately resulting in PHP code upload and execution.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-48939 · <strong>Product:</strong> iCagenda iCagenda · <strong>Class:</strong> CWE-434 / CWE-434</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>iCagenda contains an unrestricted upload of file with dangerous type vulnerability that allows the upload of arbitrary files in the file attachment feature, ultimately resulting in PHP code upload and execution.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.icagenda.com/#download\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.icagenda.com/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://github.com/Polosss/By-Poloss..-..CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://mysites.guru/blog/icagenda-zero-day-file-upload-rce/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.icagenda.com/docs/changelog/icagenda-3-9-15\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.icagenda.com/docs/changelog/icagenda-4-0-8\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 9.8) — iCagenda contains an unrestricted upload of file with dangerous type vulnerability that allows the upload of arbitrary files in the file attachment feature, ultimately resulting in PHP code upload and execution.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-48939 · <strong>Product:</strong> iCagenda iCagenda · <strong>Class:</strong> CWE-434 / CWE-434</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>iCagenda contains an unrestricted upload of file with dangerous type vulnerability that allows the upload of arbitrary files in the file attachment feature, ultimately resulting in PHP code upload and execution.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.icagenda.com/#download\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.icagenda.com/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://github.com/Polosss/By-Poloss..-..CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://mysites.guru/blog/icagenda-zero-day-file-upload-rce/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48939\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.icagenda.com/docs/changelog/icagenda-3-9-15\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.icagenda.com/docs/changelog/icagenda-4-0-8\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-48939"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-48939"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48939"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.icagenda.com/#download"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.icagenda.com/"
        },
        {
          "name": "Exploit",
          "url": "https://github.com/Polosss/By-Poloss..-..CVE-2026-48939"
        },
        {
          "name": "Reference",
          "url": "https://mysites.guru/blog/icagenda-zero-day-file-upload-rce/"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48939"
        },
        {
          "name": "Reference",
          "url": "https://www.icagenda.com/docs/changelog/icagenda-3-9-15"
        },
        {
          "name": "Reference",
          "url": "https://www.icagenda.com/docs/changelog/icagenda-4-0-8"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 70,
      "id": "zd-70",
      "cve": "CVE-2026-48908",
      "product": "JoomShaper SP Page Builder",
      "cwe": "CWE-434 / CWE-434",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "CRITICAL (CVSS 9.8) — JoomShaper SP Page Builder contains an unrestricted upload of file with dangerous type vulnerability that allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP co",
      "summary_ru": "CRITICAL (CVSS 9.8) — JoomShaper SP Page Builder contains an unrestricted upload of file with dangerous type vulnerability that allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP co",
      "practice": "file_upload",
      "owasp_note": "—",
      "flag": "FLAG{202648908}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 9.8) — JoomShaper SP Page Builder contains an unrestricted upload of file with dangerous type vulnerability that allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP co</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-48908 · <strong>Product:</strong> JoomShaper SP Page Builder · <strong>Class:</strong> CWE-434 / CWE-434</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>JoomShaper SP Page Builder contains an unrestricted upload of file with dangerous type vulnerability that allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://extensions.joomla.org/extension/sp-page-builder/\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomshaper.com/page-builder\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://mysites.guru/blog/sp-page-builder-zero-day-uploadcustomicon-rce/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.joomshaper.com/forum/question/45152\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 9.8) — JoomShaper SP Page Builder contains an unrestricted upload of file with dangerous type vulnerability that allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP co</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-48908 · <strong>Product:</strong> JoomShaper SP Page Builder · <strong>Class:</strong> CWE-434 / CWE-434</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>JoomShaper SP Page Builder contains an unrestricted upload of file with dangerous type vulnerability that allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://extensions.joomla.org/extension/sp-page-builder/\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomshaper.com/page-builder\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://mysites.guru/blog/sp-page-builder-zero-day-uploadcustomicon-rce/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48908\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.joomshaper.com/forum/question/45152\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-48908"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-48908"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48908"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://extensions.joomla.org/extension/sp-page-builder/"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.joomshaper.com/page-builder"
        },
        {
          "name": "Reference",
          "url": "https://mysites.guru/blog/sp-page-builder-zero-day-uploadcustomicon-rce/"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48908"
        },
        {
          "name": "Reference",
          "url": "https://www.joomshaper.com/forum/question/45152"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 71,
      "id": "zd-71",
      "cve": "CVE-2026-55255",
      "product": "Langflow Langflow",
      "cwe": "CWE-639",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "HIGH (CVSS 8.4) — Langflow is a tool for building and deploying AI-powered agents and workflows",
      "summary_ru": "HIGH (CVSS 8.4) — Langflow is a tool for building and deploying AI-powered agents and workflows",
      "practice": "idor",
      "owasp_note": "—",
      "flag": "FLAG{202655255}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>HIGH (CVSS 8.4) — Langflow is a tool for building and deploying AI-powered agents and workflows</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-55255 · <strong>Product:</strong> Langflow Langflow · <strong>Class:</strong> CWE-639</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.1, an Insecure Direct Object Reference (IDOR) vulnerability in /api/v1/responses endpoint allows an authenticated attacker to execute any flow belonging to another user by specifying the victim's flow ID in the request. This vulnerability is fixed in 1.9.1.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://github.com/langflow-ai/langflow/security/advisories/GHSA-qrpv-q767-xqq2\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://github.com/langflow-ai/langflow/commit/2c9f498d664a3c32698b57d7c5e752625291060e\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://github.com/langflow-ai/langflow/pull/12832\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>HIGH (CVSS 8.4) — Langflow is a tool for building and deploying AI-powered agents and workflows</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-55255 · <strong>Product:</strong> Langflow Langflow · <strong>Class:</strong> CWE-639</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to 1.9.1, an Insecure Direct Object Reference (IDOR) vulnerability in /api/v1/responses endpoint allows an authenticated attacker to execute any flow belonging to another user by specifying the victim's flow ID in the request. This vulnerability is fixed in 1.9.1.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://github.com/langflow-ai/langflow/security/advisories/GHSA-qrpv-q767-xqq2\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://github.com/langflow-ai/langflow/commit/2c9f498d664a3c32698b57d7c5e752625291060e\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://github.com/langflow-ai/langflow/pull/12832\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-55255\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-55255"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-55255"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55255"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://github.com/langflow-ai/langflow/security/advisories/GHSA-qrpv-q767-xqq2"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://github.com/langflow-ai/langflow/commit/2c9f498d664a3c32698b57d7c5e752625291060e"
        },
        {
          "name": "Reference",
          "url": "https://github.com/langflow-ai/langflow/pull/12832"
        },
        {
          "name": "Reference",
          "url": "https://webflow.sysdig.com/blog/understanding-langflow-cve-2026-55255-and-why-higher-cvss-vulnerabilities-arent-always-the-most-exploited"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-55255"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 72,
      "id": "zd-72",
      "cve": "CVE-2026-56290",
      "product": "Joomlack Page Builder",
      "cwe": "CWE-434 / CWE-434",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "CRITICAL (CVSS 9.8) — Joomlack Page Builder contains an improper access control vulnerability that could allow for remote code execution via unauthenticated arbitrary file upload.",
      "summary_ru": "CRITICAL (CVSS 9.8) — Joomlack Page Builder contains an improper access control vulnerability that could allow for remote code execution via unauthenticated arbitrary file upload.",
      "practice": "file_upload",
      "owasp_note": "—",
      "flag": "FLAG{202656290}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 9.8) — Joomlack Page Builder contains an improper access control vulnerability that could allow for remote code execution via unauthenticated arbitrary file upload.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-56290 · <strong>Product:</strong> Joomlack Page Builder · <strong>Class:</strong> CWE-434 / CWE-434</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Joomlack Page Builder contains an improper access control vulnerability that could allow for remote code execution via unauthenticated arbitrary file upload.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.joomlack.fr/en/joomla-extensions/page-builder-ck\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomlack.fr/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://forum.joomlack.fr/index.php/page-builder-ck/21627-nouvelle-version-de-pbck-et-joomla-3\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://mysites.guru/blog/pagebuilderck-unauthenticated-file-upload-rce/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 9.8) — Joomlack Page Builder contains an improper access control vulnerability that could allow for remote code execution via unauthenticated arbitrary file upload.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-56290 · <strong>Product:</strong> Joomlack Page Builder · <strong>Class:</strong> CWE-434 / CWE-434</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Joomlack Page Builder contains an improper access control vulnerability that could allow for remote code execution via unauthenticated arbitrary file upload.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.joomlack.fr/en/joomla-extensions/page-builder-ck\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomlack.fr/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://forum.joomlack.fr/index.php/page-builder-ck/21627-nouvelle-version-de-pbck-et-joomla-3\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://mysites.guru/blog/pagebuilderck-unauthenticated-file-upload-rce/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56290\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-56290"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-56290"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56290"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.joomlack.fr/en/joomla-extensions/page-builder-ck"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.joomlack.fr/"
        },
        {
          "name": "Reference",
          "url": "https://forum.joomlack.fr/index.php/page-builder-ck/21627-nouvelle-version-de-pbck-et-joomla-3"
        },
        {
          "name": "Exploit",
          "url": "https://mysites.guru/blog/pagebuilderck-unauthenticated-file-upload-rce/"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-56290"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 73,
      "id": "zd-73",
      "cve": "CVE-2026-12569",
      "product": "PTC Windchill and FlexPLM",
      "cwe": "CWE-20 / CWE-502",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "CRITICAL (CVSS 9.8) — A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill PDMlink and PTC FlexPLM",
      "summary_ru": "CRITICAL (CVSS 9.8) — A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill PDMlink and PTC FlexPLM",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{202612569}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 9.8) — A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill PDMlink and PTC FlexPLM</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-12569 · <strong>Product:</strong> PTC Windchill and FlexPLM · <strong>Class:</strong> CWE-20 / CWE-502</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill PDMlink and PTC FlexPLM. The vulnerability may be exploited through the deserialization of untrusted data. * This advisory also applies to all CPS versions * The identified vulnerability also impacts Windchill and FlexPLM releases prior to 11.0 M030</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.ptc.com/en/support/article/CS473270\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 9.8) — A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill PDMlink and PTC FlexPLM</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-12569 · <strong>Product:</strong> PTC Windchill and FlexPLM · <strong>Class:</strong> CWE-20 / CWE-502</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>A critical remote code execution (RCE) vulnerability has been reported in PTC Windchill PDMlink and PTC FlexPLM. The vulnerability may be exploited through the deserialization of untrusted data. * This advisory also applies to all CPS versions * The identified vulnerability also impacts Windchill and FlexPLM releases prior to 11.0 M030</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.ptc.com/en/support/article/CS473270\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-12569\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12569"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-12569"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-12569"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.ptc.com/en/support/article/CS473270"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-12569"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 74,
      "id": "zd-74",
      "cve": "CVE-2026-20230",
      "product": "Cisco Unified Communications Manager",
      "cwe": "CWE-918",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "HIGH (CVSS 8.6) — A vulnerability in Cisco Unified Communications Manager (Unified CM) and Cisco Unified Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, remote attacker to conduct server-",
      "summary_ru": "HIGH (CVSS 8.6) — A vulnerability in Cisco Unified Communications Manager (Unified CM) and Cisco Unified Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, remote attacker to conduct server-",
      "practice": "ssrf_rce",
      "owasp_note": "≈A01/A10",
      "flag": "FLAG{202620230}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>HIGH (CVSS 8.6) — A vulnerability in Cisco Unified Communications Manager (Unified CM) and Cisco Unified Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, remote attacker to conduct server-</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-20230 · <strong>Product:</strong> Cisco Unified Communications Manager · <strong>Class:</strong> CWE-918</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>A vulnerability in Cisco Unified Communications Manager (Unified CM) and Cisco Unified Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, remote attacker to conduct server-side request forgery (SSRF) attacks through an affected device. This vulnerability is due to improper input validation for specific HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to write files to the underlying operating system that could be used later to elevate to root. Note: Cisco has assigned this security advisory a Security Impact Rating (SIR) of Critical…</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-cucm-ssrf-cXPnHcW.html\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW\" target=\"_blank\" rel=\"noopener noreferrer\">Vendor</a></li><li><a href=\"https://denizhalil.com/2026/06/12/cve-2026-20230-cisco-unified-cm-ssrf/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>HIGH (CVSS 8.6) — A vulnerability in Cisco Unified Communications Manager (Unified CM) and Cisco Unified Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, remote attacker to conduct server-</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-20230 · <strong>Product:</strong> Cisco Unified Communications Manager · <strong>Class:</strong> CWE-918</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>A vulnerability in Cisco Unified Communications Manager (Unified CM) and Cisco Unified Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, remote attacker to conduct server-side request forgery (SSRF) attacks through an affected device. This vulnerability is due to improper input validation for specific HTTP requests. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to write files to the underlying operating system that could be used later to elevate to root. Note: Cisco has assigned this security advisory a Security Impact Rating (SIR) of Critical…</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-cucm-ssrf-cXPnHcW.html\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW\" target=\"_blank\" rel=\"noopener noreferrer\">Vendor</a></li><li><a href=\"https://denizhalil.com/2026/06/12/cve-2026-20230-cisco-unified-cm-ssrf/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-20230\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-20230"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-20230"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20230"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-cucm-ssrf-cXPnHcW.html"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Vendor",
          "url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW"
        },
        {
          "name": "Exploit",
          "url": "https://denizhalil.com/2026/06/12/cve-2026-20230-cisco-unified-cm-ssrf/"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-20230"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 75,
      "id": "zd-75",
      "cve": "CVE-2026-34910",
      "product": "Ubiquiti UniFi OS",
      "cwe": "CWE-20",
      "category": "iot",
      "category_en": "Network / IoT",
      "category_ru": "Сеть / IoT",
      "summary_en": "CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains an improper input validation vulnerability which could allow a malicious actor with access to the network to conduct command injection.",
      "summary_ru": "CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains an improper input validation vulnerability which could allow a malicious actor with access to the network to conduct command injection.",
      "practice": "cmdi",
      "owasp_note": "≈A05",
      "flag": "FLAG{202634910}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains an improper input validation vulnerability which could allow a malicious actor with access to the network to conduct command injection.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-34910 · <strong>Product:</strong> Ubiquiti UniFi OS · <strong>Class:</strong> CWE-20</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Ubiquiti UniFi OS contains an improper input validation vulnerability which could allow a malicious actor with access to the network to conduct command injection.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.pwndefend.com/2026/06/09/cve-2026-34910-exploitation-itw-building-a-botnet-mirai/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains an improper input validation vulnerability which could allow a malicious actor with access to the network to conduct command injection.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-34910 · <strong>Product:</strong> Ubiquiti UniFi OS · <strong>Class:</strong> CWE-20</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Ubiquiti UniFi OS contains an improper input validation vulnerability which could allow a malicious actor with access to the network to conduct command injection.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-34910\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.pwndefend.com/2026/06/09/cve-2026-34910-exploitation-itw-building-a-botnet-mirai/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-34910"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-34910"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-34910"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-34910"
        },
        {
          "name": "Exploit",
          "url": "https://www.pwndefend.com/2026/06/09/cve-2026-34910-exploitation-itw-building-a-botnet-mirai/"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 76,
      "id": "zd-76",
      "cve": "CVE-2026-34909",
      "product": "Ubiquiti UniFi OS",
      "cwe": "CWE-22",
      "category": "iot",
      "category_en": "Network / IoT",
      "category_ru": "Сеть / IoT",
      "summary_en": "CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains a path traversal vulnerability which could allow a malicious actor with access to the network to access files on the underlying system that could be manipulated to access an underlying account.",
      "summary_ru": "CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains a path traversal vulnerability which could allow a malicious actor with access to the network to access files on the underlying system that could be manipulated to access an underlying account.",
      "practice": "path_trav",
      "owasp_note": "≈A01",
      "flag": "FLAG{202634909}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains a path traversal vulnerability which could allow a malicious actor with access to the network to access files on the underlying system that could be manipulated to access an underlying account.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-34909 · <strong>Product:</strong> Ubiquiti UniFi OS · <strong>Class:</strong> CWE-22</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Ubiquiti UniFi OS contains a path traversal vulnerability which could allow a malicious actor with access to the network to access files on the underlying system that could be manipulated to access an underlying account.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.pwndefend.com/2026/06/09/cve-2026-34910-exploitation-itw-building-a-botnet-mirai/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 10.0) — Ubiquiti UniFi OS contains a path traversal vulnerability which could allow a malicious actor with access to the network to access files on the underlying system that could be manipulated to access an underlying account.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-34909 · <strong>Product:</strong> Ubiquiti UniFi OS · <strong>Class:</strong> CWE-22</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Ubiquiti UniFi OS contains a path traversal vulnerability which could allow a malicious actor with access to the network to access files on the underlying system that could be manipulated to access an underlying account.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-34909\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.pwndefend.com/2026/06/09/cve-2026-34910-exploitation-itw-building-a-botnet-mirai/\" target=\"_blank\" rel=\"noopener noreferrer\">Exploit</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-34909"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-34909"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-34909"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-34909"
        },
        {
          "name": "Exploit",
          "url": "https://www.pwndefend.com/2026/06/09/cve-2026-34910-exploitation-itw-building-a-botnet-mirai/"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 77,
      "id": "zd-77",
      "cve": "CVE-2026-48907",
      "product": "Widget Factory Joomla Content Editor",
      "cwe": "CWE-284",
      "category": "enterprise",
      "category_en": "Enterprise platforms",
      "category_ru": "Enterprise / ERP",
      "summary_en": "CRITICAL (CVSS 9.8) — Widget Factory Joomla Content Editor contains an improper access control vulnerability which could allow for upload and execution of PHP code via the creation of new editor profiles for unauthenticated users.",
      "summary_ru": "CRITICAL (CVSS 9.8) — Widget Factory Joomla Content Editor contains an improper access control vulnerability which could allow for upload and execution of PHP code via the creation of new editor profiles for unauthenticated users.",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{202648907}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>CRITICAL (CVSS 9.8) — Widget Factory Joomla Content Editor contains an improper access control vulnerability which could allow for upload and execution of PHP code via the creation of new editor profiles for unauthenticated users.</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-48907 · <strong>Product:</strong> Widget Factory Joomla Content Editor · <strong>Class:</strong> CWE-284</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>Widget Factory Joomla Content Editor contains an improper access control vulnerability which could allow for upload and execution of PHP code via the creation of new editor profiles for unauthenticated users.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.joomlacontenteditor.net/news/jce-security-update-and-a-free-patch-for-older-sites\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomlacontenteditor.net/support/changelog/editor\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomlacontenteditor.net/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>CRITICAL (CVSS 9.8) — Widget Factory Joomla Content Editor contains an improper access control vulnerability which could allow for upload and execution of PHP code via the creation of new editor profiles for unauthenticated users.</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-48907 · <strong>Product:</strong> Widget Factory Joomla Content Editor · <strong>Class:</strong> CWE-284</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>Widget Factory Joomla Content Editor contains an improper access control vulnerability which could allow for upload and execution of PHP code via the creation of new editor profiles for unauthenticated users.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://www.joomlacontenteditor.net/news/jce-security-update-and-a-free-patch-for-older-sites\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomlacontenteditor.net/support/changelog/editor\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.joomlacontenteditor.net/\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48907\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-48907"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-48907"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-48907"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://www.joomlacontenteditor.net/news/jce-security-update-and-a-free-patch-for-older-sites"
        },
        {
          "name": "CISA note",
          "url": "https://www.joomlacontenteditor.net/support/changelog/editor"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.joomlacontenteditor.net/"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-48907"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 78,
      "id": "zd-78",
      "cve": "CVE-2026-54420",
      "product": "LiteSpeed cPanel Plugin",
      "cwe": "CWE-61",
      "category": "hosting",
      "category_en": "Hosting infrastructure",
      "category_ru": "Хостинг-инфраструктура",
      "summary_en": "HIGH (CVSS 8.5) — LiteSpeed cPanel plugin before 2.4.8 (as distributed in LiteSpeed WHM PlugIn before 5.3.2.0) mishandles symlinks provided by a user with FTP or web shell access on a shared hosting server running CloudLinux/CageFS, as ex",
      "summary_ru": "HIGH (CVSS 8.5) — LiteSpeed cPanel plugin before 2.4.8 (as distributed in LiteSpeed WHM PlugIn before 5.3.2.0) mishandles symlinks provided by a user with FTP or web shell access on a shared hosting server running CloudLinux/CageFS, as ex",
      "practice": "rce_client",
      "owasp_note": "—",
      "flag": "FLAG{202654420}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>HIGH (CVSS 8.5) — LiteSpeed cPanel plugin before 2.4.8 (as distributed in LiteSpeed WHM PlugIn before 5.3.2.0) mishandles symlinks provided by a user with FTP or web shell access on a shared hosting server running CloudLinux/CageFS, as ex</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-54420 · <strong>Product:</strong> LiteSpeed cPanel Plugin · <strong>Class:</strong> CWE-61</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>LiteSpeed cPanel plugin before 2.4.8 (as distributed in LiteSpeed WHM PlugIn before 5.3.2.0) mishandles symlinks provided by a user with FTP or web shell access on a shared hosting server running CloudLinux/CageFS, as exploited in the wild in May 2026.</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.litespeedtech.com/products/litespeed-web-server/control-panel-support/cpanel\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>HIGH (CVSS 8.5) — LiteSpeed cPanel plugin before 2.4.8 (as distributed in LiteSpeed WHM PlugIn before 5.3.2.0) mishandles symlinks provided by a user with FTP or web shell access on a shared hosting server running CloudLinux/CageFS, as ex</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-54420 · <strong>Product:</strong> LiteSpeed cPanel Plugin · <strong>Class:</strong> CWE-61</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>LiteSpeed cPanel plugin before 2.4.8 (as distributed in LiteSpeed WHM PlugIn before 5.3.2.0) mishandles symlinks provided by a user with FTP or web shell access on a shared hosting server running CloudLinux/CageFS, as exploited in the wild in May 2026.</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.litespeedtech.com/products/litespeed-web-server/control-panel-support/cpanel\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-54420\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-54420"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-54420"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54420"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://blog.litespeedtech.com/2026/06/01/security-update-for-litespeed-cpanel-plugin-2/"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.litespeedtech.com/products/litespeed-web-server/control-panel-support/cpanel"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-54420"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 79,
      "id": "zd-79",
      "cve": "CVE-2026-20262",
      "product": "Cisco Catalyst SD-WAN Manager",
      "cwe": "CWE-22",
      "category": "edge",
      "category_en": "Edge / VPN / MDM",
      "category_ru": "Edge / VPN / MDM",
      "summary_en": "MEDIUM (CVSS 6.5) — A vulnerability in the web UI of Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, could allow an authenticated, remote attacker to create a file or overwrite any file on the filesystem of an affected system",
      "summary_ru": "MEDIUM (CVSS 6.5) — A vulnerability in the web UI of Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, could allow an authenticated, remote attacker to create a file or overwrite any file on the filesystem of an affected system",
      "practice": "path_trav",
      "owasp_note": "≈A01",
      "flag": "FLAG{202620262}",
      "points": 15,
      "diff": 3,
      "theory_en": "<h3>What it is</h3>\n<p>MEDIUM (CVSS 6.5) — A vulnerability in the web UI of Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, could allow an authenticated, remote attacker to create a file or overwrite any file on the filesystem of an affected system</p>\n<h3>Product & class</h3>\n<p><strong>CVE:</strong> CVE-2026-20262 · <strong>Product:</strong> Cisco Catalyst SD-WAN Manager · <strong>Class:</strong> CWE-22</p>\n<h3>Why outside OWASP Top 10</h3>\n<p>OWASP Top 10 covers web-application design/code. This issue often lives in OS/firmware/browser/edge layers where classic web OWASP controls do not fully apply.</p>\n<h3>What happened / why it matters</h3>\n<p>A vulnerability in the web UI of Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, could allow an authenticated, remote attacker to create a file or overwrite any file on the filesystem of an affected system. This vulnerability exists because the affected software does not properly validate user-supplied input during a file upload process. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected API endpoint of the affected system. A successful exploit could allow the attacker to create or overwrite any file on the underlying operating system. This file could later be used to elevate to root. To exploit this vulnerability, the attacker must have val…</p>\n<h3>Attack narrative</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>How defenders respond</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Sources & further reading</h3>\n<p>Aggregated from: cisa_kev, nvd. Open links to study primary material:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "theory_ru": "<h3>Что это</h3>\n<p>MEDIUM (CVSS 6.5) — A vulnerability in the web UI of Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, could allow an authenticated, remote attacker to create a file or overwrite any file on the filesystem of an affected system</p>\n<h3>Продукт и класс</h3>\n<p><strong>CVE:</strong> CVE-2026-20262 · <strong>Product:</strong> Cisco Catalyst SD-WAN Manager · <strong>Class:</strong> CWE-22</p>\n<h3>Почему вне OWASP Top 10</h3>\n<p>OWASP Top 10 — таксономия веб-приложений. Часто вектор в ОС/firmware/браузере/edge, куда не дотягиваются только веб-контроли OWASP.</p>\n<h3>Что произошло / почему важно</h3>\n<p>A vulnerability in the web UI of Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, could allow an authenticated, remote attacker to create a file or overwrite any file on the filesystem of an affected system. This vulnerability exists because the affected software does not properly validate user-supplied input during a file upload process. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected API endpoint of the affected system. A successful exploit could allow the attacker to create or overwrite any file on the underlying operating system. This file could later be used to elevate to root. To exploit this vulnerability, the attacker must have val…</p>\n<h3>Нарратив атаки</h3>\n<ul><li>Identify exposure (internet-facing appliance, client, local privilege)</li>\n<li>Trigger the vulnerability class above</li>\n<li>Escalate to RCE / LPE / data theft as in real KEV campaigns</li></ul>\n<h3>Как защищаться</h3>\n<ul><li>Patch ASAP; track CISA KEV and vendor advisories</li>\n<li>Isolate management planes; disable unused services</li>\n<li>EDR / memory integrity / least privilege</li>\n<li>Inventory internet-facing appliances (VPN/MDM/ADC)</li></ul>\n<h3>Источники и чтение</h3>\n<p>Собрано из: cisa_kev, nvd. Открой ссылки для изучения первоисточников:</p>\n<ul><li><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">NVD</a></li><li><a href=\"https://www.cve.org/CVERecord?id=CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">CVE.org</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">MITRE</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV catalog</a></li><li><a href=\"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\" target=\"_blank\" rel=\"noopener noreferrer\">CISA KEV entry</a></li><li><a href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\" target=\"_blank\" rel=\"noopener noreferrer\">CISA note</a></li><li><a href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-20262\" target=\"_blank\" rel=\"noopener noreferrer\">Reference</a></li></ul>",
      "sources": [
        {
          "name": "NVD",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-20262"
        },
        {
          "name": "CVE.org",
          "url": "https://www.cve.org/CVERecord?id=CVE-2026-20262"
        },
        {
          "name": "MITRE",
          "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20262"
        },
        {
          "name": "CISA KEV catalog",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        },
        {
          "name": "CISA KEV entry",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        },
        {
          "name": "CISA note",
          "url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
        },
        {
          "name": "CISA note",
          "url": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
        },
        {
          "name": "Reference",
          "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-20262"
        }
      ],
      "feed_from": "cisa_kev,nvd"
    },
    {
      "n": 80,
      "id": "zd-80",
      "cve": "CVE-2021-27137",
      "product": "DD-WRT DD-WRT",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "DD-WRT contains a stack-based buffer overflow vulnerability that could allow an unauthenticated attacker to overflow an internal buffer used by UPnP and trigger a code execution vulnerability.",
      "summary_ru": "DD-WRT contains a stack-based buffer overflow vulnerability that could allow an unauthenticated attacker to overflow an internal buffer used by UPnP and trigger a code execution vulnerability.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_80_cve202127137}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>DD-WRT contains a stack-based buffer overflow vulnerability that could allow an unauthenticated attacker to overflow an internal buffer used by UPnP and trigger a code execution vulnerability.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>DD-WRT contains a stack-based buffer overflow vulnerability that could allow an unauthenticated attacker to overflow an internal buffer used by UPnP and trigger a code execution vulnerability.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 81,
      "id": "zd-81",
      "cve": "CVE-2026-0770",
      "product": "Langflow Langflow",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "Langflow contains an inclusion of functionality from untrusted control sphere vulnerability that allows remote attackers to execute arbitrary code on affected installations. ",
      "summary_ru": "Langflow contains an inclusion of functionality from untrusted control sphere vulnerability that allows remote attackers to execute arbitrary code on affected installations. ",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_81_cve20260770}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>Langflow contains an inclusion of functionality from untrusted control sphere vulnerability that allows remote attackers to execute arbitrary code on affected installations. </p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>Langflow contains an inclusion of functionality from untrusted control sphere vulnerability that allows remote attackers to execute arbitrary code on affected installations. </p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 82,
      "id": "zd-82",
      "cve": "CVE-2026-60137",
      "product": "WordPress Core",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "WordPress Core contains a SQL injection vulnerability when a plugin or theme passes untrusted input to the parameter. This vulnerability can be chained with CVE-2026-63030 to allow an unauthenticated attacker to gain remote code execution on default WordPress installations.",
      "summary_ru": "WordPress Core contains a SQL injection vulnerability when a plugin or theme passes untrusted input to the parameter. This vulnerability can be chained with CVE-2026-63030 to allow an unauthenticated attacker to gain remote code execution on default WordPress installations.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_82_cve202660137}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>WordPress Core contains a SQL injection vulnerability when a plugin or theme passes untrusted input to the parameter. This vulnerability can be chained with CVE-2026-63030 to allow an unauthenticated attacker to gain remote code execution on default WordPress installations.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>WordPress Core contains a SQL injection vulnerability when a plugin or theme passes untrusted input to the parameter. This vulnerability can be chained with CVE-2026-63030 to allow an unauthenticated attacker to gain remote code execution on default WordPress installations.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 83,
      "id": "zd-83",
      "cve": "CVE-2026-63030",
      "product": "WordPress Core",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "WordPress Core contains an interpretation conflict vulnerability that could allow an attacker to perform SQL Injection and achieve Remote Code Execution. This vulnerability can be chained with CVE-2026-60137.",
      "summary_ru": "WordPress Core contains an interpretation conflict vulnerability that could allow an attacker to perform SQL Injection and achieve Remote Code Execution. This vulnerability can be chained with CVE-2026-60137.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_83_cve202663030}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>WordPress Core contains an interpretation conflict vulnerability that could allow an attacker to perform SQL Injection and achieve Remote Code Execution. This vulnerability can be chained with CVE-2026-60137.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>WordPress Core contains an interpretation conflict vulnerability that could allow an attacker to perform SQL Injection and achieve Remote Code Execution. This vulnerability can be chained with CVE-2026-60137.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 84,
      "id": "zd-84",
      "cve": "CVE-2026-16232",
      "product": "Check Point SmartConsole",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "Check Point SmartConsole contains an improper authentication vulnerability which could allow an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges.",
      "summary_ru": "Check Point SmartConsole contains an improper authentication vulnerability which could allow an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_84_cve202616232}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>Check Point SmartConsole contains an improper authentication vulnerability which could allow an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>Check Point SmartConsole contains an improper authentication vulnerability which could allow an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 85,
      "id": "zd-85",
      "cve": "CVE-2026-50522",
      "product": "Microsoft SharePoint",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "Microsoft SharePoint contains a deserialization of untrusted data vulnerability which could allow an unauthorized attacker to execute code over a network.",
      "summary_ru": "Microsoft SharePoint contains a deserialization of untrusted data vulnerability which could allow an unauthorized attacker to execute code over a network.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_85_cve202650522}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>Microsoft SharePoint contains a deserialization of untrusted data vulnerability which could allow an unauthorized attacker to execute code over a network.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>Microsoft SharePoint contains a deserialization of untrusted data vulnerability which could allow an unauthorized attacker to execute code over a network.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 86,
      "id": "zd-86",
      "cve": "CVE-2025-68686",
      "product": "Fortinet FortiOS",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "Fortinet FortiOS contains an exposure of sensitive information to an unauthorized actor vulnerability. This may allow a remote unauthenticated attacker to bypass the patch developed for the symbolic link persistency mechanism observed in some post-exploit cases, via crafted HTTP requests. An attacker would need first to have compromised the product via another vulnerability, at filesystem level.",
      "summary_ru": "Fortinet FortiOS contains an exposure of sensitive information to an unauthorized actor vulnerability. This may allow a remote unauthenticated attacker to bypass the patch developed for the symbolic link persistency mechanism observed in some post-exploit cases, via crafted HTTP requests. An attacker would need first to have compromised the product via another vulnerability, at filesystem level.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_86_cve202568686}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>Fortinet FortiOS contains an exposure of sensitive information to an unauthorized actor vulnerability. This may allow a remote unauthenticated attacker to bypass the patch developed for the symbolic link persistency mechanism observed in some post-exploit cases, via crafted HTTP requests. An attacker would need first to have compromised the product via another vulnerability, at filesystem level.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>Fortinet FortiOS contains an exposure of sensitive information to an unauthorized actor vulnerability. This may allow a remote unauthenticated attacker to bypass the patch developed for the symbolic link persistency mechanism observed in some post-exploit cases, via crafted HTTP requests. An attacker would need first to have compromised the product via another vulnerability, at filesystem level.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 87,
      "id": "zd-87",
      "cve": "CVE-2026-16812",
      "product": "Arista VeloCloud Orchestrator",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "Arista VeloCloud Orchestrator On-Prem contains an OS command injection vulnerability that may allow a remote attacker to access privileged internal functionality and impact the VCO host. Successful exploitation may compromise the confidentiality, integrity, and availability of the orchestrator and data managed by the orchestrator.",
      "summary_ru": "Arista VeloCloud Orchestrator On-Prem contains an OS command injection vulnerability that may allow a remote attacker to access privileged internal functionality and impact the VCO host. Successful exploitation may compromise the confidentiality, integrity, and availability of the orchestrator and data managed by the orchestrator.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_87_cve202616812}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>Arista VeloCloud Orchestrator On-Prem contains an OS command injection vulnerability that may allow a remote attacker to access privileged internal functionality and impact the VCO host. Successful exploitation may compromise the confidentiality, integrity, and availability of the orchestrator and data managed by the orchestrator.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>Arista VeloCloud Orchestrator On-Prem contains an OS command injection vulnerability that may allow a remote attacker to access privileged internal functionality and impact the VCO host. Successful exploitation may compromise the confidentiality, integrity, and availability of the orchestrator and data managed by the orchestrator.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    },
    {
      "n": 88,
      "id": "zd-88",
      "cve": "CVE-2026-20316",
      "product": "Cisco Secure Firewall Management Center (FMC)",
      "cwe": "CISA KEV",
      "category": "kev",
      "category_en": "CISA KEV",
      "category_ru": "CISA KEV",
      "summary_en": "Cisco Secure Firewall Management Center (FMC) formerly known as Firepower Management Center contains a use of hard-coded password vulnerability that could allow an unauthenticated, remote attacker to log in to an affected device using a low-privileged account to access sensitive data within the impacted systems.",
      "summary_ru": "Cisco Secure Firewall Management Center (FMC) formerly known as Firepower Management Center contains a use of hard-coded password vulnerability that could allow an unauthenticated, remote attacker to log in to an affected device using a low-privileged account to access sensitive data within the impacted systems.",
      "practice": "generic",
      "owasp_note": "—",
      "flag": "FLAG{zd_88_cve202620316}",
      "points": 10,
      "diff": 2,
      "theory_en": "<h3>What happened</h3><p>Cisco Secure Firewall Management Center (FMC) formerly known as Firepower Management Center contains a use of hard-coded password vulnerability that could allow an unauthenticated, remote attacker to log in to an affected device using a low-privileged account to access sensitive data within the impacted systems.</p><h3>Recommended action</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "theory_ru": "<h3>Что произошло</h3><p>Cisco Secure Firewall Management Center (FMC) formerly known as Firepower Management Center contains a use of hard-coded password vulnerability that could allow an unauthenticated, remote attacker to log in to an affected device using a low-privileged account to access sensitive data within the impacted systems.</p><h3>Рекомендуемое действие</h3><p>Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset&#x27;s internet exposure and ensuring adherence to BOD 26-04 patching guidelines.</p>",
      "sources": [
        {
          "name": "CISA KEV",
          "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
      ],
      "feed_from": "CISA KEV"
    }
  ],
  "bonuses": [
    {
      "id": "sc-shai-hulud",
      "title_en": "Shai-Hulud (npm)",
      "title_ru": "Shai-Hulud (npm)",
      "when": "2025-09",
      "note": "Self-spreading npm worm; post-install steals secrets; auto-publishes infected versions via stolen tokens; 500+ package versions; maps to OWASP A03:2025"
    },
    {
      "id": "sc-phantomraven",
      "title_en": "PhantomRaven (npm)",
      "title_ru": "PhantomRaven (npm)",
      "when": "2025-10",
      "note": "Malicious campaign across 126+ npm packages"
    },
    {
      "id": "sc-glassworm",
      "title_en": "Glassworm (VS Code)",
      "title_ru": "Glassworm (VS Code)",
      "when": "2025-10",
      "note": "Self-spreading worm via VS Code Marketplace extensions"
    }
  ],
  "intro_en": "<h3>Zero-days outside OWASP Top 10 — knowledge base</h3>\n<p><strong>Source of truth:</strong> SQLite table <code>zero_days</code>. Each card opens a <strong>full article</strong> (what / why not OWASP / technical detail / impact / defense), not a one-liner.</p>\n<p><strong>Period:</strong> late 2025 – July 2026. Sources: CISA KEV, Fortinet, Ivanti, Citrix, Cisco, Palo Alto, Apple, Google, Microsoft, Oracle, Mandiant/GTIG, Unit42, ESET, Tenable, Rapid7, SecurityWeek, TheHackerNews, BleepingComputer.</p>\n<p>OWASP Top 10 = <em>web apps you build</em>. This catalog = kernel memory safety, edge appliances, browsers, clients, hosting daemons — often KEV / APT.</p>\n<p>⚠ = conceptual overlap with an OWASP class (e.g. auth bypass ≈ A01), but the exploit path is not a typical web stack.</p>",
  "intro_ru": "<h3>Zero-day вне OWASP Top 10 — база знаний</h3>\n<p><strong>Источник правды:</strong> SQLite-таблица <code>zero_days</code>. Каждая карточка — <strong>подробная статья</strong> (что / почему не OWASP / техника / impact / защита), а не одна строка.</p>\n<p><strong>Период:</strong> конец 2025 — июль 2026. Источники: CISA KEV, Fortinet, Ivanti, Citrix, Cisco, Palo Alto, Apple, Google, Microsoft, Oracle, Mandiant/GTIG, Unit42, ESET, Tenable, Rapid7, SecurityWeek, TheHackerNews, BleepingComputer.</p>\n<p>OWASP Top 10 = <em>веб-приложения, которые вы пишете</em>. Этот каталог = memory-safety ядра, edge appliance, браузеры, клиенты, хостинг-демоны — часто KEV / APT.</p>\n<p>⚠ = пересечение с OWASP (auth bypass ≈ A01), но вектор не типовой веб-стек.</p>\n<p><strong>Почему «вне OWASP»:</strong> memory corruption в C/C++; закрытые binary appliance; клиентские утилиты; supply-chain worms без одного CVE (бонус, ≈ A03:2025).</p>"
};
