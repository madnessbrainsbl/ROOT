/* Progress, challenge flags, session state */
const Store = (() => {
  const KEY = 'owasp-emulator-v4';
  const LEGACY_KEYS = ['owasp-emulator-v3', 'owasp-emulator-v2'];

  const defaultState = () => ({
    flags: {},       // challengeId -> flag string  (also legacy A01.. keys migrated)
    quiz: {},
    tasks: {},       // module code -> true if any challenge solved
    sqlDone: {},
    hintsUsed: {},   // challengeId -> max hint level revealed (0..3)
    notes: '',
    lang: 'en',
    certName: '',
    termOpen: false,
    activeDB: 'main',
  });

  let state = defaultState();

  function load() {
    try {
      const current = localStorage.getItem(KEY);
      const raw = current || LEGACY_KEYS.map(key => localStorage.getItem(key)).find(Boolean);
      if (raw) {
        const saved = JSON.parse(raw);
        const removedChecklists = Object.prototype.hasOwnProperty.call(saved, 'checklists');
        delete saved.checklists;
        state = { ...defaultState(), ...saved };
        if (current && removedChecklists) save();
      }
      if (!current) {
        state.lang = 'en';
        save();
      }
    } catch (_) { state = defaultState(); }
    return state;
  }

  /** Call after CHALLENGES/DATA are available */
  function migrateFlags() {
    if (typeof CHALLENGES === 'undefined' || typeof DATA === 'undefined') return;
    let changed = false;
    DATA.MODS.forEach(m => {
      if (state.flags[m.code]) {
        const first = CHALLENGES.byCode(m.code)[0];
        if (first && !state.flags[first.id]) {
          state.flags[first.id] = state.flags[m.code];
          changed = true;
        }
      }
    });
    if (changed) save();
  }

  function save() {
    localStorage.setItem(KEY, JSON.stringify(state));
  }

  function get() { return state; }

  /** Capture a challenge flag by challenge id */
  function setChallengeFlag(id, flag) {
    state.flags[id] = flag;
    const ch = typeof CHALLENGES !== 'undefined' ? CHALLENGES.byId(id) : null;
    if (ch) {
      state.tasks[ch.code] = true;
      // also keep module-level flag for cert compat if primary
      const primary = CHALLENGES.byCode(ch.code)[0];
      if (primary && primary.id === id) state.flags[ch.code] = flag;
    }
    // zero-day ids (zd-*) only need flags[id]
    save();
  }

  function setFlag(codeOrId, flag) {
    // backward compat: module code or challenge id
    if (typeof CHALLENGES !== 'undefined' && CHALLENGES.byId(codeOrId)) {
      setChallengeFlag(codeOrId, flag);
      return;
    }
    if (typeof CHALLENGES !== 'undefined' && CHALLENGES.byCode(codeOrId)[0]) {
      setChallengeFlag(CHALLENGES.byCode(codeOrId)[0].id, flag);
      state.flags[codeOrId] = flag;
      state.tasks[codeOrId] = true;
      save();
      return;
    }
    state.flags[codeOrId] = flag;
    state.tasks[codeOrId] = true;
    save();
  }

  function hasFlag(codeOrId) {
    if (state.flags[codeOrId]) return true;
    if (typeof CHALLENGES !== 'undefined') {
      const ch = CHALLENGES.byId(codeOrId);
      if (ch) return !!state.flags[ch.id];
      const list = CHALLENGES.byCode(codeOrId);
      if (list.length) return list.some(c => !!state.flags[c.id]);
    }
    return false;
  }

  function hasChallenge(id) { return !!state.flags[id]; }

  function revealHint(id, level) {
    const cur = state.hintsUsed[id] || 0;
    if (level > cur) {
      state.hintsUsed[id] = level;
      save();
    }
  }

  function hintLevel(id) { return state.hintsUsed[id] || 0; }

  function markQuiz(code, qi, ok, selected) {
    if (!state.quiz[code]) {
      state.quiz[code] = { answered: {}, selected: {}, score: 0 };
    }
    const q = state.quiz[code];
    if (!q.selected) q.selected = {};
    if (q.answered[qi] == null) {
      q.answered[qi] = !!ok;
      q.selected[qi] = selected;
      if (ok) q.score = (q.score || 0) + 1;
      save();
    }
  }

  function quizProgress(code) {
    const m = typeof DATA !== 'undefined' ? DATA.MODS.find(x => x.code === code) : null;
    const total = m && m.quiz ? m.quiz.length : 0;
    const q = state.quiz[code] || { answered: {}, score: 0 };
    const answered = Object.keys(q.answered || {}).length;
    return {
      answered,
      total,
      score: q.score || 0,
      wrong: Math.max(0, answered - (q.score || 0)),
      done: total > 0 && answered >= total,
    };
  }

  function resetQuiz(code) {
    state.quiz[code] = { answered: {}, selected: {}, score: 0 };
    save();
  }

  function challengesSolved() {
    if (typeof CHALLENGES === 'undefined') return 0;
    return CHALLENGES.list.filter(c => state.flags[c.id]).length;
  }

  function challengesTotal() {
    return typeof CHALLENGES !== 'undefined' ? CHALLENGES.list.length : 10;
  }

  function pointsEarned() {
    if (typeof CHALLENGES === 'undefined') return 0;
    return CHALLENGES.list.filter(c => state.flags[c.id]).reduce((s, c) => s + c.points, 0);
  }

  function moduleChallengeProgress(code) {
    if (typeof CHALLENGES === 'undefined') return { done: hasFlag(code) ? 1 : 0, total: 1 };
    const list = CHALLENGES.byCode(code);
    const done = list.filter(c => state.flags[c.id]).length;
    return { done, total: list.length };
  }

  function moduleStatus(code) {
    const prog = moduleChallengeProgress(code);
    const qp = quizProgress(code);
    const quizDone = qp.done;
    const quizPartial = qp.answered > 0;
    const allCh = prog.done >= prog.total && prog.total > 0;
    const someCh = prog.done > 0;
    if (allCh && quizDone) return 'done';
    if (allCh || someCh || quizDone || quizPartial || state.sqlDone[code]) return 'partial';
    return 'todo';
  }

  function stats(totalMods) {
    const done = totalMods.filter(m => moduleStatus(m.code) === 'done').length;
    return {
      done,
      flags: challengesSolved(),
      total: totalMods.length,
      challenges: challengesSolved(),
      challengesTotal: challengesTotal(),
      points: pointsEarned(),
      pointsTotal: typeof CHALLENGES !== 'undefined' ? CHALLENGES.totalPoints() : 0,
    };
  }

  function allChallengesDone() {
    return challengesSolved() >= challengesTotal() && challengesTotal() > 0;
  }

  function reset() {
    state = defaultState();
    save();
  }

  function exportJSON() {
    return JSON.stringify(state, null, 2);
  }

  load();
  return {
    load, save, migrateFlags, get, setFlag, setChallengeFlag, hasFlag, hasChallenge,
    revealHint, hintLevel, markQuiz, resetQuiz, quizProgress,
    moduleStatus, moduleChallengeProgress,
    stats, challengesSolved, challengesTotal, pointsEarned, allChallengesDone,
    reset, exportJSON,
  };
})();
