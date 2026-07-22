#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build bilingual OWASP Top 10:2025 quiz from RU + EN markdown sources.

Output: js/data-labs.js quiz arrays with M(ru, en) for every field.

Correct-answer text is preserved; option order is shuffled so the right
letter is balanced across A/B/C/D. RU and EN option order stay aligned.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MD_RU = ROOT / "content" / "owasp-quiz-500-2025.md"
MD_EN = ROOT / "content" / "owasp-quiz-500-2025-en.md"
DATA_JS = ROOT / "js" / "data-labs.js"

# Quiz document category (OWASP Top 10:2025) → app lab module code (by topic)
DOC_TO_APP = {
    "A01": "A01",
    "A02": "A05",
    "A03": "A06",
    "A04": "A02",
    "A05": "A03",
    "A06": "A04",
    "A07": "A07",
    "A08": "A08",
    "A09": "A09",
    "A10": "A10",
}

ANS_IDX = {"A": 0, "B": 1, "C": 2, "D": 3}
LETTERS = ["A", "B", "C", "D"]

FILLERS_RU = [
    "Не относится к данному классу уязвимостей",
    "Исключительно клиентская (UI) проблема без серверного риска",
    "Только проблема производительности, не безопасности",
]
FILLERS_EN = [
    "Does not belong to this vulnerability class",
    "A client-side (UI) issue only, with no server-side risk",
    "Only a performance issue, not a security issue",
]


def parse_options(qtext: str) -> tuple[str, list[str]] | None:
    marks = list(re.finditer(r"(?:^|\s)([A-D])\)\s", qtext))
    if not marks:
        return None
    question = qtext[: marks[0].start()].strip()
    opts = {"A": "", "B": "", "C": "", "D": ""}
    for i, m in enumerate(marks):
        letter = m.group(1)
        start = m.end()
        end = marks[i + 1].start() if i + 1 < len(marks) else len(qtext)
        opts[letter] = qtext[start:end].strip()
    return question, [opts["A"], opts["B"], opts["C"], opts["D"]]


def parse_markdown(md: str, answer_label: str) -> dict[str, list[dict]]:
    """answer_label: 'Ответ' or 'Answer'."""
    parts = re.split(r"^## (A\d{2}:2025 — .+)$", md, flags=re.M)
    parsed: dict[str, list[dict]] = {}
    label_re = re.escape(answer_label)
    for i in range(1, len(parts), 2):
        title = parts[i]
        body = re.split(r"^---\s*$", parts[i + 1], maxsplit=1, flags=re.M)[0]
        code = title[:3]
        qs = re.findall(
            rf"(?ms)^(\d+)\.\s+(.+?)\n\s+{label_re}:\s+\*\*([A-D])\*\*(.*?)$",
            body,
        )
        items = []
        for num, qtext, ans, extra in qs:
            qtext = " ".join(qtext.split())
            po = parse_options(qtext)
            if not po:
                raise ValueError(
                    f"Cannot parse options: {code} Q{num} ({answer_label})"
                )
            question, opts = po
            expl = extra.strip()
            if expl.startswith("(") and expl.endswith(")"):
                expl = expl[1:-1].strip()
            if expl.startswith("Ответ:") or expl.startswith("Answer:"):
                expl = expl.split(":", 1)[1].strip()
            items.append(
                {
                    "n": int(num),
                    "q": question,
                    "opts": opts,
                    "ans": ans,
                    "e": expl,
                }
            )
        items.sort(key=lambda x: x["n"])
        parsed[code] = items
    return parsed


def diversify_pair(ru: dict, en: dict, global_i: int) -> dict:
    """Align RU/EN option order; balance correct letter across A–D."""
    if ru["ans"] != en["ans"]:
        raise ValueError(
            f"Answer key mismatch Q{ru['n']}: RU={ru['ans']} EN={en['ans']}"
        )
    if ru["n"] != en["n"]:
        raise ValueError(f"Question number mismatch: RU={ru['n']} EN={en['n']}")

    correct_i = ANS_IDX[ru["ans"]]
    correct_ru = ru["opts"][correct_i]
    correct_en = en["opts"][correct_i]

    dist_ru: list[str] = []
    dist_en: list[str] = []
    filler_i = 0
    for i in range(4):
        if i == correct_i:
            continue
        o_ru = (ru["opts"][i] or "").strip()
        o_en = (en["opts"][i] or "").strip()
        if not o_ru or not o_en:
            o_ru = FILLERS_RU[filler_i % len(FILLERS_RU)]
            o_en = FILLERS_EN[filler_i % len(FILLERS_EN)]
            filler_i += 1
        dist_ru.append(o_ru)
        dist_en.append(o_en)

    while len(dist_ru) < 3:
        dist_ru.append(FILLERS_RU[filler_i % len(FILLERS_RU)])
        dist_en.append(FILLERS_EN[filler_i % len(FILLERS_EN)])
        filler_i += 1
    dist_ru, dist_en = dist_ru[:3], dist_en[:3]

    target = global_i % 4
    seed = hashlib.sha256(f"{ru['q']}\0{ru['n']}\0{global_i}".encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(seed[:8], "big"))
    order = list(range(3))
    rng.shuffle(order)
    dist_ru = [dist_ru[i] for i in order]
    dist_en = [dist_en[i] for i in order]

    opts_ru = dist_ru[:]
    opts_en = dist_en[:]
    opts_ru.insert(target, correct_ru)
    opts_en.insert(target, correct_en)
    letter = LETTERS[target]

    return {
        "n": ru["n"],
        "q_ru": ru["q"],
        "q_en": en["q"],
        "opts_ru": opts_ru,
        "opts_en": opts_en,
        "ans": letter,
        "e_ru": ru.get("e") or "",
        "e_en": en.get("e") or "",
    }


def merge_and_diversify(
    ru: dict[str, list[dict]], en: dict[str, list[dict]]
) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    gi = 0
    for code in [f"A{i:02d}" for i in range(1, 11)]:
        if code not in ru or code not in en:
            raise SystemExit(f"Missing category {code} in RU or EN")
        if len(ru[code]) != 50 or len(en[code]) != 50:
            raise SystemExit(
                f"{code}: RU={len(ru[code])} EN={len(en[code])} (expected 50)"
            )
        out[code] = []
        for r, e in zip(ru[code], en[code]):
            out[code].append(diversify_pair(r, e, gi))
            gi += 1
    return out


def js_escape(s: str) -> str:
    return (
        (s or "")
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "")
        .replace("</", "<\\/")
    )


def make_quiz_js(items: list[dict]) -> str:
    lines = ["    quiz: ["]
    for it in items:
        q_ru = js_escape(it["q_ru"])
        q_en = js_escape(it["q_en"])
        e_ru = js_escape(it["e_ru"])
        e_en = js_escape(it["e_en"])
        ans = ANS_IDX[it["ans"]]
        lines.append("      {")
        lines.append(f"        q: M('{q_ru}', '{q_en}'),")
        lines.append("        opts: [")
        for o_ru, o_en in zip(it["opts_ru"], it["opts_en"]):
            lines.append(f"          M('{js_escape(o_ru)}', '{js_escape(o_en)}'),")
        lines.append("        ],")
        lines.append(f"        ans: {ans},")
        lines.append(f"        e: M('{e_ru}', '{e_en}'),")
        lines.append("      },")
    lines.append("    ],")
    return "\n".join(lines)


def update_data_js(parsed: dict[str, list[dict]]) -> None:
    src = DATA_JS.read_text(encoding="utf-8")
    app_to_doc = {v: k for k, v in DOC_TO_APP.items()}
    for app_code in [f"A{i:02d}" for i in range(1, 11)]:
        doc_code = app_to_doc[app_code]
        quiz_block = make_quiz_js(parsed[doc_code])
        pattern = rf"(code: '{app_code}'[\s\S]*?)(^[ \t]*quiz: \[[\s\S]*?^    \],)"
        m = re.search(pattern, src, re.MULTILINE)
        if not m:
            raise RuntimeError(f"quiz block not found for {app_code}")
        src = src[: m.start(2)] + quiz_block + src[m.end(2) :]
    DATA_JS.write_text(src, encoding="utf-8")


def main() -> None:
    if not MD_RU.exists():
        raise SystemExit(f"Missing source: {MD_RU}")
    if not MD_EN.exists():
        raise SystemExit(f"Missing source: {MD_EN}")

    ru = parse_markdown(MD_RU.read_text(encoding="utf-8"), "Ответ")
    en = parse_markdown(MD_EN.read_text(encoding="utf-8"), "Answer")

    for code in [f"A{i:02d}" for i in range(1, 11)]:
        if code not in ru or code not in en:
            raise SystemExit(f"Missing {code}")
        if len(ru[code]) != 50 or len(en[code]) != 50:
            raise SystemExit(
                f"{code}: RU={len(ru.get(code, []))} EN={len(en.get(code, []))}"
            )
        for r, e in zip(ru[code], en[code]):
            if r["ans"] != e["ans"]:
                raise SystemExit(
                    f"Answer mismatch {code} Q{r['n']}: RU={r['ans']} EN={e['ans']}"
                )

    parsed = merge_and_diversify(ru, en)
    dist = Counter(it["ans"] for items in parsed.values() for it in items)

    update_data_js(parsed)
    count = sum(len(items) for items in parsed.values())
    print(f"OK: {count} bilingual questions -> {DATA_JS.name}")
    print(f"correct_option distribution: {dict(sorted(dist.items()))}")


if __name__ == "__main__":
    main()
