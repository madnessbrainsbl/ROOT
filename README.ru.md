<div align="center">

![Обложка RØOT](source/cover.jpg)

# RØOT

### Ломай безопасно. Исправляй правильно.

Автономный AppSec-полигон для практики OWASP, браузерных CTF-задач,
исправления кода и исследования открытых данных CVE.

[**Демо**](https://madnessbrainsbl.github.io/ROOT/ru/) ·
[**Открыть приложение**](https://madnessbrainsbl.github.io/ROOT/app/) ·
[**English**](README.md)

[![CI](https://github.com/madnessbrainsbl/ROOT/actions/workflows/ci.yml/badge.svg)](https://github.com/madnessbrainsbl/ROOT/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-Apache--2.0-ef2b33?style=flat-square)
![Runtime](https://img.shields.io/badge/runtime-offline-22c55e?style=flat-square)

</div>

## Хватит просто читать об уязвимостях

RØOT превращает тему безопасности в повторяемый процесс: поймите границу
доверия, проэксплуатируйте контролируемую браузерную симуляцию, сравните
уязвимый и исправленный код, получите флаг и закрепите материал тестом.

Встроенное приложение работает локально. Ему не нужны SaaS-аккаунт, API-токен,
облачная лаборатория, аналитика или живая цель.

| Состав v0.1.0 | Проверенное количество |
|---|---:|
| Web CTF-задачи | 30 |
| Мини-лаборатории OWASP API Security | 10 |
| Двуязычные вопросы | 500 |
| Открытые записи CISA KEV/CVE List V5 | 250 |
| Справочные security-инструменты | 420 |
| Security-стандарты и методы | 50 |
| Payload-примеры в 66 категориях | 1 224 |
| Сценарии цепочек атак | 114 |
| Сборщики команд | 59 |

![Демонстрация RØOT](image/root-demo.gif)

## Что можно делать

- Изучать Web Top 10 с CWE и практическим контекстом.
- Проходить безопасные Web- и API-симуляции с подсказками и баллами.
- Сравнивать уязвимый код с конкретным исправлением.
- Искать в локальном публичном CVE-снимке по ID, вендору, продукту и severity.
- Использовать payloads, attack chains, command builders, чек-листы, SQL и
  шаблоны отчётов.
- Хранить прогресс и заметки в браузере и экспортировать их в JSON.

![Теория, практика, исправление и тест OWASP](image/owasp-lab.jpg)

## Быстрый старт

Требования: Python 3.10+ и современный браузер.

```powershell
git clone https://github.com/madnessbrainsbl/ROOT.git
cd ROOT
python serve.py
```

Откройте <http://127.0.0.1:8080/> для лендинга или
<http://127.0.0.1:8080/app/> для самого приложения.

### Docker

```bash
docker compose up --build
```

Контейнер открывает <http://127.0.0.1:8080> и создаёт SQLite в отдельной
временной файловой системе. Секреты и внешние токены не нужны.

## Данные CVE и offline-режим

В RØOT входит небольшой снимок из 250 недавно добавленных записей CISA Known
Exploited Vulnerabilities. Опубликованные записи CVE List V5 дополняют их
данными CNA, если они доступны.

- Источники и SHA-256: [`data/cves_public.provenance.json`](data/cves_public.provenance.json)
- Воспроизводимый генератор: [`scripts/build_cve_seed.py`](scripts/build_cve_seed.py)
- Условия использования сторонних компонентов и источники: ниже.

Явное обновление для сопровождающих проекта:

```powershell
python scripts/build_cve_seed.py --limit 250
```

Приложение ничего не загружает при старте и не имеет endpoint для токенов или
обновления. Python-сервер использует SQLite, а GitHub Pages фильтрует тот же
JSON-снимок прямо в браузере.

Локальный `python3 serve.py` автоматически использует игнорируемые Git файлы
`data/cves_NNN.json`, если они есть, и сохраняет их fingerprint в SQLite.
`ROOT_CVE_MODE=public` принудительно включает публичный seed на 250 записей;
GitHub Pages и Docker по умолчанию работают именно с ним.
На медленной общей файловой системе можно задать `ROOT_DB_BUILD_DIR=/tmp`:
временная база соберётся локально и затем атомарно заменит постоянную.

![Поиск по открытому CVE-снимку](image/cve-catalog.jpg)

## Архитектура

```text
Браузер (Vanilla JS)
├── Единый раздел OWASP: Web / API / LLM / ASVS
├── SDLC security frameworks: STRIDE / SSDF / SLSA / CWE / CVSS / CIS
├── CTF-симуляции, тесты, tools, payloads и отчёты
├── Рабочая база sql.js + прогресс в браузере
└── GET /api/cves → Python stdlib server → SQLite
```

У Python-runtime нет сторонних пакетов. Данные frontend разделены по предметным
областям без bundler и фреймворка.

### Read-only API

```text
GET /api/health
GET /api/cves/status
GET /api/cves?severity=CRITICAL&q=apache&limit=50&offset=0
GET /api/cves/counts
GET /api/cves/{CVE-ID}
```

## Ограничения

- RØOT — учебный симулятор, а не сканер уязвимостей.
- CVE-снимок не является полной или оперативной threat-intelligence базой.
- Прогресс привязан к текущему профилю браузера.
- Важные сведения о CVE нужно проверять по advisory вендора.

## Ответственное использование

RØOT предназначен для обучения и проверки систем, которые принадлежат вам или
на проверку которых есть явное разрешение. Не используйте примеры, payloads,
симуляции и команды проекта для доступа к чужим системам, нарушения их работы,
изменения или извлечения данных. Соблюдайте закон, договоры, правила программ и
процедуры согласованного раскрытия уязвимостей.

Встроенный снимок CVE служит учебным материалом, а не оперативной threat
intelligence. Перед рабочим решением сверяйте важные сведения с записью CVE,
CISA KEV и advisory производителя.

## Сообщение об уязвимости

Сообщайте об уязвимостях RØOT через форму GitHub **Report a vulnerability**,
если она доступна. Если нет, создайте issue только с безопасным кратким
описанием и запросите приватный канал связи. Укажите версию, шаги
воспроизведения, влияние и минимальный proof of concept; не публикуйте
учётные данные, персональные данные или данные чужих систем.

Лаборатории намеренно содержат уязвимые сценарии. Это не ошибка безопасности,
пока поведение не выходит за пределы локальной симуляции.

## Вклад в проект

Делайте небольшие сфокусированные изменения, не добавляйте production-зависимости
без согласования и прикладывайте минимальный релевантный тест. В материалах
указывайте источники и лицензии. Не добавляйте проприетарный контент, секреты,
данные реальных целей, платные учебные материалы или наборы payloads без
совместимой атрибуции. Вклад распространяется по Apache-2.0.

## История версий

**0.1.0, 2026-07-22:** добавлены двуязычные лендинги, ссылки на разделы
приложения, открытый снимок CISA KEV/CVE List V5, read-only CVE API, Docker и
CI для релизов. Убраны проприетарная синхронизация CVE, обработка учётных данных
и загрузки при запуске.

Проект распространяется по Apache-2.0 без гарантий. Тексты лицензий находятся
в каталоге [`licenses/`](licenses/).

## Сторонние компоненты и источники

RØOT распространяется по Apache-2.0. Для перечисленных ниже компонентов и
данных действуют их собственные лицензии или условия использования.

| Компонент или данные | Лицензия / условия | Использование в RØOT |
|---|---|---|
| [sql.js](https://github.com/sql-js/sql.js) | MIT | `js/vendor/sql-wasm.js` и `js/vendor/sql-wasm.wasm` обеспечивают SQL-среду в браузере. Текст лицензии: `licenses/sql.js-LICENSE.txt`. |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | MIT | В справочнике payloads есть адаптированные примеры. Атрибуция и лицензия: `licenses/PayloadsAllTheThings-LICENSE.txt`. |
| [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) | CC BY-SA 4.0 | В обзоре ASVS используются официальные версия, уровни и структура глав. Описания RØOT учебные; первоисточник остаётся авторитетным. |
| Space Grotesk, JetBrains Mono, Orbitron, VT323 | SIL Open Font License 1.1 | Локально размещённые веб-шрифты. Текст лицензии: `licenses/fonts-OFL-1.1.txt`. |
| [CISA KEV](https://github.com/cisagov/kev-data) | Открытые данные правительства США; см. уведомления источника | Поставляет включённую выборку Known Exploited Vulnerabilities. |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | См. условия CVE Program и уведомления репозитория | Поставляет опубликованные описания CNA, затронутые продукты, CWE и CVSS, если они доступны. |

Источники CVE-снимка, время генерации, количество записей и SHA-256 указаны в
`data/cves_public.provenance.json`. Пересобрать снимок можно командой
`python scripts/build_cve_seed.py --limit 250`.

### Стандарты и учебные источники

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Software Assurance Maturity Model](https://owasp.org/www-project-samm/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Mobile Application Security](https://mas.owasp.org/)
- [OWASP LLM Security Verification Standard](https://owasp.org/www-project-llm-verification-standard/)
- [OWASP Threat Modeling](https://owasp.org/www-project-threat-modeling/)
- [NIST Secure Software Development Framework, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [SLSA specification 1.2](https://slsa.dev/spec/v1.2/)
- [Common Weakness Enumeration](https://cwe.mitre.org/)
- [Common Attack Pattern Enumeration and Classification](https://capec.mitre.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [Common Vulnerability Scoring System 4.0](https://www.first.org/cvss/v4.0/)
- [Exploit Prediction Scoring System](https://www.first.org/epss/)
- [CISA SSVC](https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

Названия, идентификаторы и товарные знаки принадлежат соответствующим открытым
стандартам и каталогам. Они не означают одобрения RØOT со стороны OWASP, NIST,
MITRE, CISA, CVE Program, FIRST, Linux Foundation или Center for Internet
Security. Описания RØOT учебные; связанные первоисточники являются авторитетными.

Код приложения RØOT, двуязычные объяснения, интерфейс, сценарии симулированных
лабораторий, организация цепочек атак и шаблоны отчётов распространяются по
лицензии проекта, если выше не указано иное. Иллюстрации и скриншоты в `source/`
и `image/` покрываются лицензией проекта, если в самом файле не указано другое.
