/* RØOT — Top 10 прикладных направлений LLM
 * Оригинальный образовательный материал (не OWASP risk list).
 * Каждая карточка: суть · роль LLM · примеры · детали · security-hint для RØOT.
 */
const LlmTop10 = (() => {
  const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const numLabel = (id) => { const m = String(id).match(/(\d+)$/); return m ? String(+m[1]).padStart(2,'0') : String(id); };

  const INTRO = {
    en: `<p class="theory-lead"><strong>Top 10 LLM application areas</strong> — where large language models actually land in products and business processes. Not a risk taxonomy (see OWASP LLM Top 10 for that); this is a map of <em>what</em> people build.</p>
<p>Each direction: core idea, how LLMs help, real scenarios, implementation notes, and a short security pointer. Offline notes only — no model weights.</p>
<p>In practice directions combine: a support bot that extracts structured fields, summarizes, and drafts a code fix is already three areas at once.</p>`,
    ru: `<p class="theory-lead"><strong>Топ‑10 прикладных направлений LLM</strong> — куда большие языковые модели реально внедряются в продукты и бизнес-процессы. Это не таксономия рисков (для угроз есть OWASP LLM Top 10), а карта <em>что</em> строят.</p>
<p>У каждого направления: суть, роль LLM, типичные сценарии, детали внедрения и короткий security-hint. Только offline-заметки; веса моделей не грузятся.</p>
<p>На практике направления почти всегда комбинируются: support-бот, который извлекает поля, суммаризирует диалог и набрасывает SQL/скрипт — уже три области сразу.</p>`,
  };

  const ITEMS = [
    {
      id: 'LLM01',
      title_en: 'Chatbots & virtual assistants',
      title_ru: 'Чат-боты и виртуальные ассистенты',
      body_en: `<p><strong>Core idea.</strong> Dialog systems that hold a natural conversation: answer questions, run commands, hand off to a human, and stay in character for a brand or role (support, sales, internal HR/IT).</p>
<p><strong>How LLMs help.</strong> Modern models (GPT-4-class, Claude, Gemini, open weights) keep multi-turn context, infer intent from messy phrasing, and generate coherent replies — far beyond keyword trees and rigid flows.</p>
<ul>
<li><strong>Examples:</strong> website/app support chat; voice assistants; Slack/Teams corporate bots; onboarding guides; booking/order status agents.</li>
<li><strong>Stack patterns:</strong> system prompt + tool calling (CRM, tickets, calendar); <strong>RAG</strong> over policy/docs so answers stay on-brand and factual; multi-language “out of the box”.</li>
<li><strong>Details:</strong> separate “channel UX” (widgets, voice STT/TTS) from “brain” (LLM + retrieval + tools). Log turns for quality review; add human takeover when confidence is low or policy says so.</li>
<li><strong>Security (RØOT):</strong> treat every user message and every retrieved doc as untrusted (<em>prompt injection</em>); least-privilege tools; no secrets in the system prompt; rate limits on cost/DoS.</li>
<li><strong>Real-world / public cases:</strong> 2023 research on <em>Bing Chat</em> showed <em>indirect prompt injection</em> via untrusted web pages the assistant summarized; public write-ups on early ChatGPT <em>plugins</em> demonstrated cross-plugin data exfiltration patterns when tools trusted model output. Class of incidents: support bots that auto-act on tool calls after a single user message.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> primarily <em>LLM01 Prompt Injection</em>; also <em>LLM06 Excessive Agency</em>, <em>LLM07 System Prompt Leakage</em>, <em>LLM10 Unbounded Consumption</em>.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Диалоговые системы, которые ведут естественный разговор: отвечают на вопросы, выполняют команды, передают диалог человеку и держат тон бренда/роли (поддержка, продажи, внутренний HR/IT).</p>
<p><strong>Роль LLM.</strong> Современные модели (класс GPT‑4, Claude, Gemini, open-weights) держат длинный контекст, понимают намерение из «кривого» текста и генерируют связные ответы — это уже не keyword-деревья и жёсткие сценарии.</p>
<ul>
<li><strong>Примеры:</strong> чат поддержки на сайте/в приложении; голосовые ассистенты; корпоративные боты в Slack/Teams; онбординг; агенты статуса заказа/бронирования.</li>
<li><strong>Паттерны стека:</strong> system prompt + tool calling (CRM, тикеты, календарь); <strong>RAG</strong> по регламентам и базе знаний, чтобы ответы были «по документу»; многоязычность «из коробки».</li>
<li><strong>Детали:</strong> отделяйте UX-канал (виджет, голос STT/TTS) от «мозга» (LLM + retrieval + tools). Логируйте реплики для QA; human takeover при низкой уверенности или по политике.</li>
<li><strong>Security (RØOT):</strong> любое сообщение пользователя и любой retrieved-документ — untrusted (<em>prompt injection</em>); least-privilege на tools; без секретов в system prompt; rate limits от cost/DoS.</li>
<li><strong>Реальные / публичные кейсы:</strong> исследования 2023 по <em>Bing Chat</em> — <em>indirect prompt injection</em> через недоверенные веб-страницы, которые ассистент суммаризировал; публичные разборы ранних <em>plugins</em> ChatGPT — паттерны data exfil между плагинами, когда tools доверяют output модели. Класс инцидентов: support-боты, которые сразу дергают tools по одному сообщению.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> в первую очередь <em>LLM01 Prompt Injection</em>; также <em>LLM06 Excessive Agency</em>, <em>LLM07 System Prompt Leakage</em>, <em>LLM10 Unbounded Consumption</em>.</li>
</ul>`,
    },
    {
      id: 'LLM02',
      title_en: 'Content generation (copy, marketing, docs)',
      title_ru: 'Генерация контента (тексты, маркетинг, docs)',
      body_en: `<p><strong>Core idea.</strong> Draft and rewrite text at scale: social posts, email, landing copy, product descriptions, internal docs, scripts — with controllable tone, length, and structure.</p>
<p><strong>How LLMs help.</strong> They produce stylistically varied, on-topic prose from a brief; rewrite for audience/SEO; expand outlines into full sections; keep brand voice via few-shot examples or a style card in the prompt.</p>
<ul>
<li><strong>Examples:</strong> SEO articles and meta descriptions; marketplace product cards; newsroom first drafts; ad variants (A/B); release notes from tickets.</li>
<li><strong>Details:</strong> prompt engineering locks format (list / table / JSON for CMS), keywords, and reading level. Often wired to CMS, Notion, or a content calendar. Human edit remains the quality gate for public copy.</li>
<li><strong>Security (RØOT):</strong> do not paste confidential drafts into public APIs without a DPA/private deployment; watch for training-data leakage of competitor/brand secrets; citation/fact-check for claims.</li>
<li><strong>Real-world / public cases:</strong> widely reported class of incidents (e.g. Samsung employees pasting source/meeting notes into ChatGPT, 2023 press) — confidential material left the org boundary via consumer SaaS LLM. Marketing teams shipping AI-drafted claims without fact-check created misinformation / compliance risk.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM02 Sensitive Information Disclosure</em>, <em>LLM09 Misinformation</em>; policy side of <em>LLM10 Unbounded Consumption</em> when bulk generation runs unmetered.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Черновики и переписывание текстов в масштабе: посты, email, лендинги, карточки товаров, внутренняя документация, сценарии — с контролем тона, длины и структуры.</p>
<p><strong>Роль LLM.</strong> Генерируют осмысленный, стилистически разный текст по брифу; адаптируют под аудиторию/SEO; разворачивают outline в разделы; держат tone of voice через few-shot или «карточку стиля» в промпте.</p>
<ul>
<li><strong>Примеры:</strong> SEO-статьи и meta; карточки маркетплейсов; черновики новостей; варианты рекламы (A/B); release notes из тикетов.</li>
<li><strong>Детали:</strong> промпт-инжиниринг фиксирует формат (список / таблица / JSON под CMS), ключи и уровень языка. Часто связка с CMS, Notion, контент-календарём. Для публичного текста human edit — обязательный quality gate.</li>
<li><strong>Security (RØOT):</strong> не сливать конфиденциальные черновики в публичные API без DPA/private deploy; следить за утечкой брендовых/конкурентных секретов; fact-check утверждений.</li>
<li><strong>Реальные / публичные кейсы:</strong> широко освещавшийся класс инцидентов (сотрудники Samsung и др. вставляли код/заметки в ChatGPT, 2023) — конфиденциальные данные ушли за периметр через consumer SaaS LLM. Маркетинг без fact-check AI-черновиков — risk misinformation / compliance.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM02 Sensitive Information Disclosure</em>, <em>LLM09 Misinformation</em>; политика вокруг <em>LLM10 Unbounded Consumption</em> при bulk-генерации без лимитов.</li>
</ul>`,
    },
    {
      id: 'LLM03',
      title_en: 'Code generation & explanation',
      title_ru: 'Генерация и объяснение кода',
      body_en: `<p><strong>Core idea.</strong> Assist writing, debugging, refactoring, migrating, and documenting software — inside the IDE or as a chat pair-programmer.</p>
<p><strong>How LLMs help.</strong> Models trained on large code corpora (Copilot-class, Code Llama / StarCoder family, general frontier models) emit functions, tests, SQL, infra snippets, and explain opaque code in plain language.</p>
<ul>
<li><strong>Examples:</strong> inline autocomplete; “generate unit tests for this module”; SQL from a business question; language-to-language porting; explain a legacy algorithm “like I’m new on the team”.</li>
<li><strong>Details:</strong> best results with repo context (open files, symbols, linter errors). Comment-as-spec works well. Always run tests/linters — models invent APIs that do not exist.</li>
<li><strong>Security (RØOT):</strong> never paste production secrets into the assistant; review for insecure patterns (SQLi, hard-coded keys, path traversal); supply-chain risk if you accept random package names the model “suggested”.</li>
<li><strong>Real-world / public cases:</strong> academic and industry studies (e.g. NYU/Stanford-style evaluations of Copilot-class assistants) found models often suggest insecure patterns (weak crypto, injection-prone snippets). Separately, “package hallucination” research showed invented dependency names that attackers can squat — a supply-chain class risk.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM05 Improper Output Handling</em> (host app executes model code/SQL), <em>LLM03 Supply Chain</em>, <em>LLM02 Sensitive Information Disclosure</em> when secrets enter the chat.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Помощь в написании, отладке, рефакторинге, миграции и документировании кода — в IDE или как pair-programmer в чате.</p>
<p><strong>Роль LLM.</strong> Модели, обученные на огромных корпусах кода (класс Copilot, семейства Code Llama / StarCoder, общие frontier-модели), пишут функции, тесты, SQL, infra-фрагменты и объясняют «чужой» код человеческим языком.</p>
<ul>
<li><strong>Примеры:</strong> inline-автодополнение; «напиши unit-тесты к модулю»; SQL по бизнес-описанию; порт между языками; разбор legacy-алгоритма «для новичка в команде».</li>
<li><strong>Детали:</strong> лучший результат с контекстом репозитория (открытые файлы, символы, ошибки линтера). Комментарий-как-спека работает хорошо. Всегда гоняйте тесты/линтеры — модели выдумывают несуществующие API.</li>
<li><strong>Security (RØOT):</strong> не вставлять prod-секреты в ассистента; ревью на insecure patterns (SQLi, hard-coded keys, path traversal); supply-chain риск, если слепо ставите «предложенные» пакеты.</li>
<li><strong>Реальные / публичные кейсы:</strong> академические и индустриальные оценки ассистентов класса Copilot — частые insecure patterns (слабая крипто, injection-prone сниппеты). Отдельно: research по «package hallucination» — выдуманные имена зависимостей, которые можно squat’ить (supply-chain класс).</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM05 Improper Output Handling</em> (host исполняет код/SQL модели), <em>LLM03 Supply Chain</em>, <em>LLM02 Sensitive Information Disclosure</em>, если секреты попали в чат.</li>
</ul>`,
    },
    {
      id: 'LLM04',
      title_en: 'Text summarization',
      title_ru: 'Суммаризация текстов',
      body_en: `<p><strong>Core idea.</strong> Compress long material into a short brief without losing the decisions, numbers, and risks that matter to the reader.</p>
<p><strong>How LLMs help.</strong> Strong at <em>abstractive</em> summaries (rewrite, not just cherry-pick sentences): bullets for execs, “what changed since last week”, thread digests, paper abstracts, meeting notes from transcripts.</p>
<ul>
<li><strong>Examples:</strong> news digests; email/thread rollups; research paper abstracts; call-center post-call notes; contract “key obligations” extracts.</li>
<li><strong>Details:</strong> control length and audience in the prompt (“5 bullets for legal”, “one paragraph for sales”). For long docs, map-reduce / hierarchical summarize (chunk → partials → merge). Prefer grounded mode with source quotes when accuracy matters.</li>
<li><strong>Security (RØOT):</strong> summaries can invent numbers (hallucination) — require citations for high-impact use; do not summarize sensitive corpora into a channel with broader ACLs.</li>
<li><strong>Real-world / public cases:</strong> enterprise “meeting notes → shared channel” pipelines repeatedly surface over-sharing: a summary of a restricted call lands in a wider Slack/Teams room. News/media demos of abstractive summaries inventing quotes or figures illustrate the high-impact hallucination class.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM09 Misinformation</em> (hallucinated facts in briefs), <em>LLM02 Sensitive Information Disclosure</em> via ACL widening on the summary channel.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Сжать большой объём текста до краткого содержания, не потеряв решения, цифры и риски, важные читателю.</p>
<p><strong>Роль LLM.</strong> Сильны в <em>абстрактивной</em> суммаризации (переформулировка, а не только вырезание предложений): буллиты для руководства, «что изменилось за неделю», дайджесты тредов, abstracts статей, заметки созвона из транскрипта.</p>
<ul>
<li><strong>Примеры:</strong> новостные дайджесты; свёртка переписок; рефераты papers; post-call notes в support; «ключевые обязательства» из договора.</li>
<li><strong>Детали:</strong> длину и аудиторию задавайте в промпте («5 буллитов для legal», «абзац для sales»). Для длинных документов — map-reduce / иерархия (чанки → частичные → merge). Когда важна точность — grounded-режим с цитатами источников.</li>
<li><strong>Security (RØOT):</strong> саммари может выдумать цифры (hallucination) — для high-impact требуйте citations; не суммаризируйте sensitive-корпус в канал с более широкими ACL.</li>
<li><strong>Реальные / публичные кейсы:</strong> enterprise-пайплайны «заметки созвона → общий канал» часто over-share: саммари закрытого митинга попадает в широкий Slack/Teams. Медиа-демо абстрактивных саммари с выдуманными цитатами/цифрами — класс high-impact hallucination.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM09 Misinformation</em> (выдуманные факты в briefs), <em>LLM02 Sensitive Information Disclosure</em> через расширение ACL у канала саммари.</li>
</ul>`,
    },
    {
      id: 'LLM05',
      title_en: 'Translation & localization',
      title_ru: 'Перевод и локализация',
      body_en: `<p><strong>Core idea.</strong> Move product and content across languages while keeping meaning, tone, and domain terms consistent — not word-for-word MT dumps.</p>
<p><strong>How LLMs help.</strong> Multilingual models trained on parallel and monolingual data handle idioms, register, and mixed-language input better than classic phrase-based MT; they can apply a glossary and rewrite for culture (transcreation-lite).</p>
<ul>
<li><strong>Examples:</strong> UI string catalogs; marketing localization; live chat translation; support macros in N languages; subtitle drafts.</li>
<li><strong>Details:</strong> feed a glossary / TM (translation memory) in-context for consistent product names. Separate “literal translation” vs “adapt for market X”. Human review for legal/medical and brand-critical lines.</li>
<li><strong>Security (RØOT):</strong> translating internal docs via a public API is a data-exfil path; lock tenants and audit what left the org boundary.</li>
<li><strong>Real-world / public cases:</strong> same “paste internal PDF into free translator / consumer LLM” class as content generation — roadmaps, contracts, and medical notes leave the perimeter. Live chat translation that logs both languages can create a second, broader retention surface for PII.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM02 Sensitive Information Disclosure</em>; quality failures map to <em>LLM09 Misinformation</em> when legal/medical meaning drifts.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Перенос продукта и контента между языками с сохранением смысла, тона и терминов — не «машинный перевод слово-в-слово».</p>
<p><strong>Роль LLM.</strong> Многоязычные модели лучше классического MT держат идиомы, регистр и mixed-language ввод; умеют применять глоссарий и слегка адаптировать под культуру (лёгкая transcreation).</p>
<ul>
<li><strong>Примеры:</strong> каталоги UI-строк; локализация маркетинга; live-перевод в чатах; support-макросы на N языках; черновики субтитров.</li>
<li><strong>Детали:</strong> глоссарий / TM (translation memory) в контексте — единые имена продуктов. Разделяйте «буквальный перевод» и «адаптация под рынок X». Human review для legal/med и brand-critical строк.</li>
<li><strong>Security (RØOT):</strong> перевод внутренних docs через публичный API — путь утечки; tenant isolation и аудит того, что ушло за периметр.</li>
<li><strong>Реальные / публичные кейсы:</strong> тот же класс «вставил внутренний PDF в free translator / consumer LLM» — roadmap, договоры, medical notes уходят за периметр. Live-перевод чатов с логом обоих языков создаёт вторую, более широкую поверхность хранения PII.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM02 Sensitive Information Disclosure</em>; сдвиг смысла в legal/med → <em>LLM09 Misinformation</em>.</li>
</ul>`,
    },
    {
      id: 'LLM06',
      title_en: 'Sentiment & opinion mining',
      title_ru: 'Анализ тональности и извлечение мнений',
      body_en: `<p><strong>Core idea.</strong> Label emotional polarity and extract <em>what</em> people like/hate (aspect-based), not just a single positive/negative score.</p>
<p><strong>How LLMs help.</strong> They handle sarcasm, mixed sentiment, and domain slang better than bag-of-words classifiers; can return structured JSON: aspect → polarity → evidence quote.</p>
<ul>
<li><strong>Examples:</strong> review mining for products; brand social listening; employee survey themes; ticket urgency / anger detection for routing.</li>
<li><strong>Details:</strong> define your scale (3-class, 5-star, NPS-style). Few-shot examples beat a bare prompt. Batch offline for cost; real-time only for routing/alerts. Calibrate on a gold set — LLMs still drift by language and niche.</li>
<li><strong>Security (RØOT):</strong> employee/customer text is often PII — minimize retention; be careful with automated HR decisions (bias, policy, regulation).</li>
<li><strong>Real-world / public cases:</strong> social-listening and review-mining products historically over-collected public posts into vendor clouds (PII + opinion profiles). Automated “anger score → HR/performance” experiments in industry press highlight bias and unlawful automated decision-making risks under GDPR-style regimes.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM02 Sensitive Information Disclosure</em> (PII in training/logs), governance side of <em>LLM09 Misinformation</em> when polarity labels drive automated actions without human review.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Определить эмоциональную окраску и вытащить <em>о чём</em> мнение (aspect-based), а не одну метку «позитив/негатив».</p>
<p><strong>Роль LLM.</strong> Лучше bag-of-words справляются с сарказмом, смешанными эмоциями и сленгом; умеют отдать JSON: аспект → полярность → цитата-доказательство.</p>
<ul>
<li><strong>Примеры:</strong> разбор отзывов; social listening бренда; темы из опросов сотрудников; детект злости/срочности в тикетах для маршрутизации.</li>
<li><strong>Детали:</strong> зафиксируйте шкалу (3 класса, 5 звёзд, NPS-style). Few-shot бьёт «голый» промпт. Офлайн-батчи для экономии; realtime — только для routing/алертов. Калибруйте на gold-set — дрейф по языку и нише остаётся.</li>
<li><strong>Security (RØOT):</strong> тексты клиентов/сотрудников часто PII — минимизируйте хранение; осторожно с авто-решениями в HR (bias, политики, регуляторика).</li>
<li><strong>Реальные / публичные кейсы:</strong> social-listening и review-mining продукты исторически утаскивали публичные посты в облака вендоров (PII + opinion profiles). Эксперименты «anger score → HR/performance» в индустриальной прессе — bias и риски automated decision-making (GDPR-like режимы).</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM02 Sensitive Information Disclosure</em> (PII в training/логах); governance вокруг <em>LLM09 Misinformation</em>, когда метки полярности двигают авто-действия без human review.</li>
</ul>`,
    },
    {
      id: 'LLM07',
      title_en: 'Question answering (QA over knowledge)',
      title_ru: 'Question Answering (ответы по знаниям)',
      body_en: `<p><strong>Core idea.</strong> Answer a user question from a <em>controlled</em> corpus (or model knowledge) with a short, attributable reply — not a free-form essay.</p>
<p><strong>How LLMs help.</strong> They parse the question, fuse retrieved passages, and write a natural answer. With RAG, the model only sees chunks relevant to the query → fewer hallucinations and fresher facts than parametric memory alone.</p>
<ul>
<li><strong>Examples:</strong> enterprise knowledge search; policy/FAQ bots; technical doc assistants; regulated domains (legal/medical) with mandatory citations.</li>
<li><strong>Details:</strong> pipeline = embed → retrieve top-k → (optional re-rank) → generate with “answer only from context”. Support factoid (date, name) and explanatory answers. Track citation click-through as a quality metric.</li>
<li><strong>Security (RØOT):</strong> enforce ACLs <em>before</em> retrieval (tenant isolation); poison-resistant indexes; never put secrets only in the prompt — put them outside the model’s reach.</li>
<li><strong>Real-world / public cases:</strong> multi-tenant RAG demos and bug reports where retrieval ignored document ACLs → cross-customer knowledge leak. Research on <em>indirect prompt injection via RAG</em> (malicious docs in the corpus instruct the model to exfiltrate prior context). Classic “vector store has more data than the UI ever showed.”</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM08 Vector and Embedding Weaknesses</em>, <em>LLM01 Prompt Injection</em> (indirect via corpus), <em>LLM02 Sensitive Information Disclosure</em>, <em>LLM04 Data and Model Poisoning</em>.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Точный ответ на вопрос по <em>контролируемому</em> корпусу (или знаниям модели) — коротко и с опорой на источник, а не свободное эссе.</p>
<p><strong>Роль LLM.</strong> Парсят вопрос, склеивают найденные фрагменты и пишут естественный ответ. В RAG модель видит только релевантные чанки → меньше галлюцинаций и свежее факты, чем только «память весов».</p>
<ul>
<li><strong>Примеры:</strong> корпоративный поиск по базе знаний; policy/FAQ-боты; ассистенты по техдокам; regulated-домены (legal/med) с обязательными цитатами.</li>
<li><strong>Детали:</strong> пайплайн = embed → retrieve top-k → (опц. re-rank) → generate «отвечай только из контекста». Фактоиды (дата, имя) и развёрнутые объяснения. Метрика качества — клики по citations.</li>
<li><strong>Security (RØOT):</strong> ACL <em>до</em> retrieval (tenant isolation); устойчивость индекса к poisoning; секреты не «только в prompt» — вне досягаемости модели.</li>
<li><strong>Реальные / публичные кейсы:</strong> multi-tenant RAG-демо и багрепорты, где retrieval игнорировал ACL документов → утечка знаний между клиентами. Research: <em>indirect prompt injection через RAG</em> (вредоносный doc в корпусе заставляет модель exfil контекста). Классика: «в vector store больше данных, чем UI когда-либо показывал».</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM08 Vector and Embedding Weaknesses</em>, <em>LLM01 Prompt Injection</em> (indirect через корпус), <em>LLM02 Sensitive Information Disclosure</em>, <em>LLM04 Data and Model Poisoning</em>.</li>
</ul>`,
    },
    {
      id: 'LLM08',
      title_en: 'Education & tutoring',
      title_ru: 'Образование и тьюторинг',
      body_en: `<p><strong>Core idea.</strong> Personal coach that explains concepts, drills practice, grades work with feedback, and generates learning materials at the learner’s level.</p>
<p><strong>How LLMs help.</strong> Socratic dialogue, multi-level explanations (ELI5 → expert), worked examples, misconception detection, and adaptive quizzes — all from one model with a good tutoring prompt.</p>
<ul>
<li><strong>Examples:</strong> math/programming tutors; exam question banks; essay feedback; language practice partner; corporate L&amp;D micro-lessons.</li>
<li><strong>Details:</strong> set pedagogy in the system prompt (don’t dump answers immediately; ask for steps). Ground on a curriculum/RAG textbook for accuracy. Log learning traces for teachers, not only for the student UI.</li>
<li><strong>Security (RØOT):</strong> student data is sensitive; block jailbreaks that turn the tutor into a cheat sheet for closed exams if policy forbids it; verify STEM facts on high-stakes content.</li>
<li><strong>Real-world / public cases:</strong> universities and exam boards publicly debated AI-assisted cheating with general chatbots (2023–2024). EdTech products that store full student transcripts face FERPA/GDPR-class retention risk; STEM tutors inventing wrong “facts” on high-stakes content is a documented product-quality class.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM01 Prompt Injection</em> / jailbreak past tutoring policy, <em>LLM09 Misinformation</em>, <em>LLM02 Sensitive Information Disclosure</em> (student data).</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Персональный помощник: объясняет, тренирует, проверяет работы с фидбеком и генерирует учебные материалы под уровень ученика.</p>
<p><strong>Роль LLM.</strong> Сократический диалог, объяснения на разных уровнях (ELI5 → expert), разобранные примеры, ловля типичных заблуждений, адаптивные квизы — из одной модели при хорошем tutoring-промпте.</p>
<ul>
<li><strong>Примеры:</strong> репетитор по математике/коду; банк экзаменационных вопросов; фидбек по эссе; языковой partner; микро-уроки L&amp;D в компании.</li>
<li><strong>Детали:</strong> педагогику кладите в system prompt (не выдавать ответ сразу; просить ход решения). Grounding на curriculum/RAG-учебнике для точности. Логи для преподавателя, не только UI ученика.</li>
<li><strong>Security (RØOT):</strong> данные учеников — sensitive; блокируйте jailbreak «напиши ответы к закрытому экзамену», если политика запрещает; STEM-факты на high-stakes — проверяйте.</li>
<li><strong>Реальные / публичные кейсы:</strong> университеты и exam boards публично обсуждали AI-cheating через общие чат-боты (2023–2024). EdTech с полными транскриптами учеников — FERPA/GDPR-класс retention risk; STEM-тьюторы с выдуманными «фактами» на high-stakes — задокументированный product-quality класс.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM01 Prompt Injection</em> / jailbreak мимо tutoring-политики, <em>LLM09 Misinformation</em>, <em>LLM02 Sensitive Information Disclosure</em> (student data).</li>
</ul>`,
    },
    {
      id: 'LLM09',
      title_en: 'Data extraction & structuring',
      title_ru: 'Извлечение и структурирование данных',
      body_en: `<p><strong>Core idea.</strong> Turn messy text (emails, PDFs, scans+OCR, chat logs) into tables, JSON, or ERP fields for automation and analytics.</p>
<p><strong>How LLMs help.</strong> Entity and relation extraction with tolerance for typos, varied layouts, and paraphrases; fill a fixed schema (JSON Schema / function calling) more flexibly than brittle regex.</p>
<ul>
<li><strong>Examples:</strong> resume parsing; contract clause extraction; invoice → ERP lines; clinical note → coded facts; support ticket field auto-fill.</li>
<li><strong>Details:</strong> always validate against schema; reject/repair invalid JSON; hybrid with OCR + layout models for scans. Confidence thresholds + human review for money/legal fields. Idempotent pipelines for retries.</li>
<li><strong>Security (RØOT):</strong> extracted output that is later executed (SQL, shell, HTML) needs the same encoding as any untrusted input — <em>improper output handling</em>; minimize PII in logs.</li>
<li><strong>Real-world / public cases:</strong> invoice/OCR→ERP pipelines that accept attacker-controlled PDF fields have driven classic injection into backends when extracted strings are concatenated into SQL or shell. Resumes and clinical notes extraction create large PII lakes in vendor logs — a recurring due-diligence finding in enterprise LLM reviews.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM05 Improper Output Handling</em>, <em>LLM02 Sensitive Information Disclosure</em>, <em>LLM01 Prompt Injection</em> when untrusted document text steers extraction instructions.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> Превратить «грязный» текст (письма, PDF, сканы+OCR, логи чатов) в таблицы, JSON или поля ERP для автоматизации и аналитики.</p>
<p><strong>Роль LLM.</strong> Извлечение сущностей и связей с толерантностью к опечаткам, разной вёрстке и перефразировкам; заполнение жёсткой схемы (JSON Schema / function calling) гибче, чем хрупкий regex.</p>
<ul>
<li><strong>Примеры:</strong> парсинг резюме; пункты договоров; счёт-фактура → строки ERP; эпикриз → структурированные факты; автозаполнение полей тикета.</li>
<li><strong>Детали:</strong> всегда валидируйте схему; reject/repair битого JSON; hybrid с OCR + layout-моделями для сканов. Пороги confidence + human review на деньги/legal. Идемпотентные пайплайны для retry.</li>
<li><strong>Security (RØOT):</strong> output, который потом исполняют (SQL, shell, HTML), кодируйте как untrusted input — <em>improper output handling</em>; минимизируйте PII в логах.</li>
<li><strong>Реальные / публичные кейсы:</strong> пайплайны invoice/OCR→ERP, принимающие attacker-controlled PDF, ведут к classic injection в backend, если extracted-строки склеивают в SQL/shell. Извлечение резюме и clinical notes создаёт PII-озёра в логах вендора — частая finding в enterprise LLM due diligence.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM05 Improper Output Handling</em>, <em>LLM02 Sensitive Information Disclosure</em>, <em>LLM01 Prompt Injection</em>, когда untrusted текст документа рулит инструкциями извлечения.</li>
</ul>`,
    },
    {
      id: 'LLM10',
      title_en: 'Creative writing & ideation',
      title_ru: 'Творческое письмо и генерация идей',
      body_en: `<p><strong>Core idea.</strong> Use the model as a sparring partner for names, plots, concepts, slogans, storyboards — volume first, then refine with human taste.</p>
<p><strong>How LLMs help.</strong> Broad combinatorial knowledge + instruction following: “50 brand names”, lateral-thinking prompts, style transfers, iterative improve-from-feedback loops that kill blank-page paralysis.</p>
<ul>
<li><strong>Examples:</strong> brand naming; headline variants; game world bibles; draft poems/scripts; campaign concepts; workshop warm-ups.</li>
<li><strong>Details:</strong> separate diverge (many options) from converge (score, critique, merge). Techniques: “six hats”, constraints (“without using the letter e”), role prompts. Keep a shortlist outside the chat so good ideas don’t drown in scrollback.</li>
<li><strong>Security (RØOT):</strong> IP/copyright: check trademarks and training-data lookalikes before shipping a name; don’t invent “customer testimonials” for real products (misinformation / fraud risk).</li>
<li><strong>Real-world / public cases:</strong> brands that shipped AI-generated slogans later found near-duplicates of existing marks (trademark disputes / forced rebrands — a public IP class). Fake “customer reviews” and AI news filler without disclosure triggered platform takedowns and advertising-compliance actions.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM09 Misinformation</em>; IP/training-data lookalikes sit next to <em>LLM03 Supply Chain</em> / governance of model outputs used commercially.</li>
</ul>`,
      body_ru: `<p><strong>Суть.</strong> LLM как спарринг-партнёр для имён, сюжетов, концепций, слоганов, раскадровок — сначала объём вариантов, потом отбор человеческим вкусом.</p>
<p><strong>Роль LLM.</strong> Широкая «комбинаторика» знаний + следование инструкциям: «50 названий бренда», латеральные промпты, перенос стиля, циклы improve-from-feedback, которые снимают страх чистого листа.</p>
<ul>
<li><strong>Примеры:</strong> нейминг; варианты заголовков; bible мира для игры; черновики стихов/сценариев; креативы кампаний; разминка на воркшопах.</li>
<li><strong>Детали:</strong> разделите diverge (много вариантов) и converge (оценка, критика, merge). Техники: «шесть шляп», ограничения («без буквы е»), role-prompts. Shortlist храните вне чата, чтобы сильные идеи не утонули в истории.</li>
<li><strong>Security (RØOT):</strong> IP/copyright: проверяйте товарные знаки и «похожие» чужие артефакты до релиза имени; не выдумывайте «отзывы клиентов» для реальных продуктов (misinformation / fraud).</li>
<li><strong>Реальные / публичные кейсы:</strong> бренды, выкатившие AI-слоганы, позже находили near-duplicates существующих знаков (trademark / rebrand — публичный IP-класс). Фейковые «отзывы клиентов» и AI news filler без disclosure — takedown и advertising-compliance.</li>
<li><strong>OWASP LLM Top 10 (2025):</strong> <em>LLM09 Misinformation</em>; IP/training-data lookalikes рядом с <em>LLM03 Supply Chain</em> / governance коммерческого использования output.</li>
</ul>`,
    },
  ];

  const QUIZ = [
    {
      q_en: 'RAG in a corporate chatbot is mainly used to…',
      q_ru: 'RAG в корпоративном чат-боте в первую очередь нужен, чтобы…',
      opts_en: ['Make the model smaller', 'Ground answers in internal docs and reduce free hallucination', 'Replace the need for any access control', 'Train a new foundation model nightly'],
      opts_ru: ['Сделать модель меньше', 'Опирать ответы на внутренние docs и снизить «свободные» галлюцинации', 'Заменить любой access control', 'Каждую ночь обучать foundation model'],
      ans: 1,
    },
    {
      q_en: 'Turning LLM output into SQL/HTML without encoding is closest to…',
      q_ru: 'Подставлять output LLM в SQL/HTML без encoding — это ближе всего к…',
      opts_en: ['Harmless summarization', 'Improper output handling (injection into the host app)', 'Better SEO only', 'Required for localization'],
      opts_ru: ['Безопасной суммаризации', 'Improper output handling (injection в host-приложение)', 'Только лучшему SEO', 'Обязательному шагу локализации'],
      ans: 1,
    },
    {
      q_en: 'Which pattern best fits “invoice PDF → ERP fields”?',
      q_ru: 'Какой паттерн лучше всего подходит под «PDF счёта → поля ERP»?',
      opts_en: ['Creative ideation only', 'Schema-constrained extraction (+ OCR if scanned)', 'Voice TTS only', 'Unbounded agent with cloud admin keys'],
      opts_ru: ['Только креативный brainstorm', 'Извлечение по схеме (+ OCR, если скан)', 'Только голосовой TTS', 'Агент с cloud admin keys без ограничений'],
      ans: 1,
    },
  ];

  function renderHub() {
    const en = I18n.lang() === 'en';
    return `
      <div class="lab-page">
        <div class="hero hub-compact">
          <div class="row mb8" style="flex-wrap:wrap;gap:6px">
            <span class="tag tc">LLM</span>
            <span class="tag tb">Applications</span>
            <span class="tag tm">Top 10</span>
            <span class="tag th">use cases</span>
          </div>
          <h1 style="color:var(--txt)">${en ? 'Top 10 LLM application areas' : 'Топ‑10 прикладных направлений LLM'}</h1>
          <p class="hub-intro-short">${en
            ? 'Where LLMs are actually used: chat, content, code, RAG QA, extraction, education, and more. Offline notes; no model weights.'
            : 'Куда реально внедряют LLM: чаты, контент, код, RAG-QA, извлечение данных, образование и др. Offline-заметки; веса моделей не грузятся.'}</p>
          <div class="row" style="flex-wrap:wrap;gap:6px;margin-top:8px">
            ${ITEMS.map(it =>
              `<button type="button" class="chip" onclick="UI.route('llm10','${esc(it.id)}')">${esc(it.id)}</button>`
            ).join('')}
            <button type="button" class="btn" onclick="document.getElementById('llm-intro')?.classList.toggle('hidden')">${en ? 'About' : 'О разделе'}</button>
          </div>
          <div class="theory hub-intro-full hidden" id="llm-intro">${en ? INTRO.en : INTRO.ru}</div>
        </div>

        ${ITEMS.map(it => `
          <div class="card" id="llm-${esc(it.id)}" style="color:var(--txt)">
            <div class="ch" style="cursor:pointer" onclick="UI.route('llm10','${esc(it.id)}')" title="${en ? 'Open' : 'Открыть'}">
              <span class="lab-code" style="margin-right:8px">${esc(numLabel(it.id))}</span>
              <h2 style="color:var(--txt)">${esc(en ? it.title_en : it.title_ru)}</h2>
            </div>
            <div class="cb" style="color:var(--txt);font-size:14.5px;line-height:1.7">
              ${en ? it.body_en : it.body_ru}
              <div class="row" style="margin-top:12px">
                <button type="button" class="btn btnp btns" onclick="UI.route('llm10','${esc(it.id)}')">${en ? 'Open page' : 'Открыть страницу'} →</button>
              </div>
            </div>
          </div>`).join('')}

        <div class="card" style="color:var(--txt)">
          <div class="ch"><h2 style="color:var(--txt)">${en ? 'How areas combine' : 'Как направления комбинируются'}</h2></div>
          <div class="cb" style="color:var(--txt);line-height:1.7">
            <p>${en
              ? 'Real products almost never ship a single area in isolation. Typical combos:'
              : 'Реальные продукты почти никогда не живут одним направлением. Типичные связки:'}</p>
            <ul>
              <li>${en
                ? '<strong>Support agent:</strong> chat (01) + RAG QA (07) + summarization (04) + ticket field extraction (09).'
                : '<strong>Support-агент:</strong> чат (01) + RAG QA (07) + суммаризация (04) + извлечение полей тикета (09).'}</li>
              <li>${en
                ? '<strong>Content ops:</strong> generation (02) + translation (05) + sentiment on comments (06).'
                : '<strong>Контент-ops:</strong> генерация (02) + перевод (05) + тональность комментариев (06).'}</li>
              <li>${en
                ? '<strong>Dev workspace:</strong> code assist (03) + doc QA (07) + meeting summary (04).'
                : '<strong>Dev workspace:</strong> code assist (03) + QA по докам (07) + саммари митингов (04).'}</li>
            </ul>
            <p class="muted small">${en
              ? 'Security risks (prompt injection, data leak, excessive agency, unbounded cost) cut across all ten — see OWASP Top 10 for LLM Applications for the threat view.'
              : 'Риски (prompt injection, утечки, excessive agency, unbounded cost) режут все десять направлений — threat-view: OWASP Top 10 for LLM Applications.'}</p>
          </div>
        </div>

        <div class="card" style="color:var(--txt)">
          <div class="ch"><h2 style="color:var(--txt)">${en ? 'Quick quiz' : 'Быстрый квиз'}</h2></div>
          <div class="cb">
            ${QUIZ.map((q, qi) => `
              <div class="qblock" style="margin-bottom:16px">
                <div class="qt" style="color:var(--txt);font-weight:600;margin-bottom:8px">${qi + 1}. ${esc(en ? q.q_en : q.q_ru)}</div>
                <div class="qopts">
                  ${(en ? q.opts_en : q.opts_ru).map((o, oi) =>
                    `<button type="button" class="btn" style="display:block;width:100%;text-align:left;margin-bottom:6px"
                      onclick="LlmTop10.ans(${qi},${oi},this)">${esc(o)}</button>`
                  ).join('')}
                </div>
                <div class="qe" id="llm-qe-${qi}"></div>
              </div>`).join('')}
          </div>
        </div>

        <div class="card" style="color:var(--txt)">
          <div class="ch"><h2 style="color:var(--txt)">${en ? 'Related RØOT modules' : 'Связанные модули RØOT'}</h2></div>
          <div class="cb row" style="flex-wrap:wrap;gap:8px">
            <button class="btn" onclick="UI.route('apihub')">API Top 10</button>
            <button class="btn" onclick="UI.route('webtop10')">Web Top 10:2025</button>
            <button class="btn" onclick="UI.route('lab','A03')">A03 Injection lab</button>
            <button class="btn" onclick="UI.route('lab','A01')">A01 Access lab</button>
          </div>
        </div>
      </div>`;
  }

  function renderItem(id) {
    const it = ITEMS.find(x => x.id === id);
    if (!it) {
      return `<div class="card"><div class="cb">${I18n.lang() === 'en' ? 'Not found' : 'Не найдено'}</div>
        <div class="cb"><button class="btn" onclick="UI.route('llmhub')">← LLM Top 10</button></div></div>`;
    }
    const en = I18n.lang() === 'en';
    const idx = ITEMS.findIndex(x => x.id === id);
    const prev = idx > 0 ? ITEMS[idx - 1] : null;
    const next = idx >= 0 && idx < ITEMS.length - 1 ? ITEMS[idx + 1] : null;
    return `
      <div class="lab-page">
        <div class="row mb12" style="flex-wrap:wrap;gap:8px">
          <button class="btn" onclick="UI.route('llmhub')">← LLM Top 10</button>
          ${prev ? `<button class="btn" onclick="UI.route('llm10','${esc(prev.id)}')">← ${esc(prev.id)}</button>` : ''}
          ${next ? `<button class="btn" onclick="UI.route('llm10','${esc(next.id)}')">${esc(next.id)} →</button>` : ''}
        </div>
        <div class="card lab-card">
          <div class="ch lab-header">
            <div class="lab-title">
              <span class="lab-code">${esc(numLabel(it.id))}</span>
              <div>
                <h2>${esc(en ? it.title_en : it.title_ru)}</h2>
                <div class="lab-sub">${en ? 'LLM application area' : 'Прикладное направление LLM'}</div>
              </div>
            </div>
            <span class="tag tb">LLM</span>
          </div>
          <div class="tabs" id="llm-tabs" role="tablist">
            <button type="button" class="tab active" data-tab="theory">${en ? 'Theory' : 'Теория'}</button>
          </div>
          <div class="tabpane active" id="tp-theory" role="tabpanel">
            <div class="theory" style="max-width:none">${en ? it.body_en : it.body_ru}</div>
          </div>
        </div>
      </div>`;
  }

  function bindTabs() {
    document.querySelectorAll('#llm-tabs .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('#llm-tabs .tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.lab-card .tabpane').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tp-' + tab.dataset.tab)?.classList.add('active');
      });
    });
  }

  function ans(qi, oi, btn) {
    const q = QUIZ[qi];
    const ok = oi === q.ans;
    const box = document.getElementById('llm-qe-' + qi);
    if (box) {
      box.classList.add('show');
      box.innerHTML = ok
        ? `<div class="resp ok">${I18n.lang()==='en'?'Correct':'Верно'}</div>`
        : `<div class="resp err">${I18n.lang()==='en'?'Not quite — pick another':'Не то — выбери другой вариант'}</div>`;
    }
    if (btn) btn.classList.add(ok ? 'btng' : 'btnd');
  }

  return { renderHub, renderItem, bindTabs, ans, ITEMS };
})();
