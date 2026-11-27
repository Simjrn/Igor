from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import unicodedata
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import streamlit as st

ROOT = Path(__file__).parent
COURSES_DIR = ROOT / "courses"
DB_PATH = ROOT / ".igor_progress.db"
AUDIO_EXTENSIONS = (".mp3", ".wav", ".ogg", ".m4a", ".webm")

TEXT = {
    "en": {
        "tagline":"Small steps. Strong shell.", "learn":"Learn", "log_in":"Log in", "sign_up":"Create account",
        "username":"Username", "password":"Password", "logout":"Log out", "welcome":"Welcome back",
        "choose_course":"Choose your course", "lesson":"Lesson", "start":"Start lesson", "continue":"Continue",
        "xp":"XP", "streak":"day streak", "lessons_done":"lessons completed", "check":"Check answer",
        "next":"Continue", "correct":"Nice work!", "incorrect":"Not quite — try again.",
        "finish":"Lesson complete!", "finish_body":"You kept moving. Every little step counts.", "back":"Back to lessons",
        "no_courses":"No courses are available yet.", "audio_missing":"Audio isn't available for this question yet.",
        "pick":"Choose an answer", "write_here":"Type your translation", "wordbank_hint":"Tap words to build your answer.",
        "source":"Match these", "target":"with these", "empty":"Choose an option",
        "already":"That username is already taken.", "bad_login":"Username or password is incorrect.",
        "create_first":"Create an account to save your XP, streak, and lesson progress.", "language":"Interface language",
        "question_of":"Question", "correct_answer":"A good answer:", "no_lessons":"This course has no lessons yet.",
    },
    "es": {
        "tagline":"Pasos pequeños. Caparazón fuerte.", "learn":"Aprender", "log_in":"Iniciar sesión", "sign_up":"Crear cuenta",
        "username":"Usuario", "password":"Contraseña", "logout":"Cerrar sesión", "welcome":"¡Qué bueno verte!",
        "choose_course":"Elige tu curso", "lesson":"Lección", "start":"Empezar lección", "continue":"Continuar",
        "xp":"XP", "streak":"días seguidos", "lessons_done":"lecciones completadas", "check":"Comprobar",
        "next":"Continuar", "correct":"¡Muy bien!", "incorrect":"Casi — inténtalo otra vez.",
        "finish":"¡Lección completada!", "finish_body":"Seguiste avanzando. Cada paso cuenta.", "back":"Volver a las lecciones",
        "no_courses":"Todavía no hay cursos disponibles.", "audio_missing":"El audio aún no está disponible para esta pregunta.",
        "pick":"Elige una respuesta", "write_here":"Escribe tu traducción", "wordbank_hint":"Pulsa palabras para formar tu respuesta.",
        "source":"Relaciona", "target":"con", "empty":"Elige una opción",
        "already":"Ese usuario ya existe.", "bad_login":"El usuario o la contraseña no son correctos.",
        "create_first":"Crea una cuenta para guardar tus XP, racha y progreso.", "language":"Idioma de la interfaz",
        "question_of":"Pregunta", "correct_answer":"Una respuesta válida:", "no_lessons":"Este curso todavía no tiene lecciones.",
    },
}

st.set_page_config(page_title="Igor · Language learning", page_icon="🐢", layout="centered")
st.html("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800;900&display=swap');
:root { --igor:#27734f; --igor-dark:#174b35; --mint:#e8f4ec; }
html, body, [class*="css"] { font-family:'Nunito',sans-serif; }
.stApp { background:linear-gradient(180deg,#f6fbf7 0%,#fff 48%); }
.block-container { max-width:760px; padding-top:1.4rem; }
.igor-brand { color:var(--igor-dark); display:flex; align-items:center; gap:12px; font-size:1.55rem; font-weight:900; }
.igor-shell { display:inline-grid; place-items:center; height:48px; width:48px; border-radius:50%; background:var(--igor); color:white; font-size:29px; box-shadow:inset -5px -5px 0 #174b35; }
.igor-sub { color:#658173; font-weight:700; font-size:.88rem; margin-top:-6px; }
.stats { padding:12px 16px; border-radius:15px; background:#edf6ef; color:#24583e; font-weight:800; }
.question-label { color:var(--igor); font-size:.82rem; font-weight:900; letter-spacing:.08em; text-transform:uppercase; }
div.stButton > button[kind="primary"] { background:var(--igor); border-color:var(--igor); border-radius:13px; font-weight:900; min-height:2.8rem; }
div.stButton > button { border-radius:12px; }
</style>
""")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            salt BLOB NOT NULL, password_hash BLOB NOT NULL, ui_language TEXT NOT NULL DEFAULT 'en',
            xp INTEGER NOT NOT NULL DEFAULT 0, streak INTEGER NOT NULL DEFAULT 0,
            last_active TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS completed_lessons (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            course_id TEXT NOT NULL, lesson_id TEXT NOT NULL, completed_at TEXT NOT NULL,
            PRIMARY KEY(user_id, course_id, lesson_id)
        );
        """)


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)


def register(username: str, password: str, language: str) -> bool:
    name = username.strip()
    if len(name) < 3 or len(name) > 24 or not re.fullmatch(r"[\\w.-]+", name, flags=re.UNICODE) or len(password) < 8:
        return False
    salt = secrets.token_bytes(16)
    try:
        with db() as conn:
            conn.execute("INSERT INTO users(username,salt,password_hash,ui_language,created_at) VALUES(?,?,?,?,?)",
                         (name, salt, password_digest(password, salt), language, datetime.utcnow().isoformat()))
        return True
    except sqlite3.IntegrityError:
        return False


def authenticate(username: str, password: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username.strip(),)).fetchone()
    if row and hmac.compare_digest(row["password_hash"], password_digest(password, row["salt"])):
        return dict(row)
    return None


def get_user(user_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def courses() -> list[dict[str, Any]]:
    found = []
    for path in sorted(COURSES_DIR.glob("*/course.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["_path"] = path.parent
            data["id"] = data.get("id", path.parent.name)
            if isinstance(data.get("lessons"), list): found.append(data)
        except (OSError, json.JSONDecodeError):
            continue
    return found


def normalize(text: Any) -> str:
    value = unicodedata.normalize("NFKD", str(text or "").casefold().strip())
    value = "".join(c for c in value if not unicodedata.combining(c))
    return re.sub(r"[^\\w]+", " ", value, flags=re.UNICODE).strip()


def audio_path(course: dict, question: dict) -> Path | None:
    folder = course["_path"] / "audio"
    if not folder.is_dir(): return None
    candidates = [str(question["audio"])] if question.get("audio") else []
    keys = [question.get("text"), question.get("prompt"), question.get("answer"), question.get("audio_text")]
    for key in keys:
        if key:
            slug = re.sub(r"[^a-z0-9]+", "-", normalize(key)).strip("-")
            candidates.extend(slug + ext for ext in AUDIO_EXTENSIONS)
    for candidate in candidates:
        item = folder / Path(candidate).name
        if item.is_file() and item.suffix.lower() in AUDIO_EXTENSIONS:
            return item
    return None


def audio_widget(course: dict, question: dict, t: dict) -> None:
    path = audio_path(course, question)
    if path:
        try:
            st.audio(path.read_bytes(), format={".mp3":"audio/mpeg",".wav":"audio/wav",".ogg":"audio/ogg",".m4a":"audio/mp4",".webm":"audio/webm"}.get(path.suffix.lower()))
        except (OSError, Exception):
            st.caption(t["audio_missing"])
    else:
        st.caption(t["audio_missing"])


def completed_ids(user_id: int, course_id: str) -> set[str]:
    with db() as conn:
        rows = conn.execute("SELECT lesson_id FROM completed_lessons WHERE user_id=? AND course_id=?", (user_id, course_id)).fetchall()
    return {r[0] for r in rows}


def award_xp(user_id: int, points: int = 5) -> None:
    with db() as conn:
        conn.execute("UPDATE users SET xp=xp+? WHERE id=?", (points, user_id))


def finish_lesson(user_id: int, course_id: str, lesson_id: str) -> None:
    today = date.today()
    with db() as conn:
        user = conn.execute("SELECT streak,last_active FROM users WHERE id=?", (user_id,)).fetchone()
        already = conn.execute("SELECT 1 FROM completed_lessons WHERE user_id=? AND course_id=? AND lesson_id=?", (user_id, course_id, lesson_id)).fetchone()
        if already: return
        previous = date.fromisoformat(user["last_active"]) if user["last_active"] else None
        streak = user["streak"] if previous == today else (user["streak"] + 1 if previous == today - timedelta(days=1) else 1)
        conn.execute("UPDATE users SET streak=?,last_active=? WHERE id=?", (streak, today.isoformat(), user_id))
        conn.execute("INSERT INTO completed_lessons(user_id,course_id,lesson_id,completed_at) VALUES(?,?,?,?)", (user_id, course_id, lesson_id, datetime.utcnow().isoformat()))


def header(t: dict) -> None:
    st.html(f'<div class="igor-brand"><span class="igor-shell">🐢</span><span>Igor<div class="igor-sub">{t["tagline"]}</div></span></div>')
    st.write("")


def render_auth() -> None:
    lang = st.selectbox("Interface language / Idioma de la interfaz", ["English", "Español"])
    ui = "es" if lang == "Español" else "en"
    t = TEXT[ui]
    header(t)
    st.markdown(f"### {t['welcome']}")
    st.caption(t["create_first"])
    mode = st.radio("", [t["log_in"], t["sign_up"]], horizontal=True, label_visibility="collapsed")
    with st.form("auth_form"):
        username = st.text_input(t["username"], max_chars=24)
        password = st.text_input(t["password"], type="password")
        submitted = st.form_submit_button(t["continue"], type="primary", use_container_width=True)
    if submitted:
        if mode == t["sign_up"]:
            if len(password) < 8:
                st.error("Use at least 8 characters." if ui == "en" else "Usa al menos 8 caracteres.")
            elif register(username, password, ui):
                st.session_state.user = authenticate(username, password)
                st.rerun()
            elif len(username.strip()) < 3:
                st.error("Username must be at least 3 characters." if ui == "en" else "El usuario debe tener al menos 3 caracteres.")
            else:
                st.error(t["already"])
        else:
            user = authenticate(username, password)
            if user:
                st.session_state.user = user
                st.rerun()
            else:
                st.error(t["bad_login"])


def normalize_answer(text: Any) -> str:
    return normalize(text)


def render_question(course: dict, question: dict, number: int, total: int, t: dict, user_id: int) -> None:
    qtype = question.get("type", "multiple_choice")
    st.progress(number / max(total, 1))
    st.markdown(f'<div class="question-label">{t["question_of"]} {number} / {total}</div>', unsafe_allow_html=True)
    st.markdown(f"## {question.get('prompt', question.get('text', 'Translate this'))}")
    qkey = f"answer_{st.session_state.lesson_token}_{number}"
    checked_key = qkey + "_checked"
    if checked_key not in st.session_state: st.session_state[checked_key] = None

    with st.form("question_form_" + qkey):
        value: Any = None
        if qtype in ("multiple_choice", "listen"):
            if qtype == "listen": audio_widget(course, question, t)
            value = st.radio(t["pick"], question.get("options", []), index=None, key=qkey, label_visibility="collapsed")
        elif qtype == "write":
            value = st.text_input(t["write_here"], key=qkey)
        elif qtype == "word_bank":
            st.caption(t["wordbank_hint"])
            value = " ".join(st.multiselect(t["write_here"], question.get("words", []), key=qkey))
        elif qtype == "gap":
            st.markdown(question.get("sentence", "___"))
            value = st.text_input(t["write_here"], key=qkey)
        elif qtype in ("match", "audio_match"):
            pairs = question.get("pairs", [])
            value = {}
            choices = [p.get("right", "") for p in pairs]
            for i, pair in enumerate(pairs):
                left = pair.get("left", "")
                if qtype == "audio_match":
                    audio_widget(course, {"audio":pair.get("audio"), "text":pair.get("audio_text", left)}, t)
                value[left] = st.selectbox(f"{left}  →", [t["empty"]] + choices, key=f"{qkey}_{i}")
        else:
            st.error(f"Unsupported question type: {qtype}")
        submitted = st.form_submit_button(t["check"], type="primary", use_container_width=True)

    if submitted:
        if qtype in ("multiple_choice", "listen", "write", "word_bank", "gap"):
            accepted = question.get("accepted", [question.get("answer", "")])
            if not isinstance(accepted, list): accepted = [accepted]
            is_correct = normalize_answer(value) in {normalize_answer(x) for x in accepted}
        elif qtype in ("match", "audio_match"):
            pairs = question.get("pairs", [])
            is_correct = bool(pairs) and all(value.get(p["left"]) == p["right"] for p in pairs)
        else:
            is_correct = False
        st.session_state[checked_key] = is_correct
        if is_correct and not st.session_state.get(qkey + "_awarded"):
            award_xp(user_id)
            st.session_state[qkey + "_awarded"] = True
        st.rerun()

    result = st.session_state.get(checked_key)
    if result is True:
        st.success(t["correct"] + "  +5 XP")
        if st.button(t["next"], key="next_" + qkey, type="primary", use_container_width=True):
            st.session_state.question_index += 1
            st.rerun()
    elif result is False:
        st.error(t["incorrect"])
        if qtype in ("write", "word_bank", "gap"):
            st.caption(f"{t['correct_answer']} {question.get('answer','')}")
        if st.button(t["continue"], key="retry_" + qkey, use_container_width=True):
            st.session_state[checked_key] = None
            st.session_state.pop(qkey, None)
            st.rerun()


def render_app() -> None:
    user = get_user(st.session_state.user["id"])
    if not user:
        st.session_state.pop("user", None)
        st.rerun()
    ui = user["ui_language"] if user["ui_language"] in TEXT else "en"
    t = TEXT[ui]
    header(t)
    with st.sidebar:
        st.markdown(f"### 🐢 {user['username']}")
        st.markdown(f"**{user['xp']} {t['xp']}**  ·  **🔥 {user['streak']} {t['streak']}**")
        new_ui = st.selectbox(t["language"], ["en", "es"], index=0 if ui == "en" else 1, format_func=lambda x:"English" if x == "en" else "Español")
        if new_ui != ui:
            with db() as conn:
                conn.execute("UPDATE users SET ui_language=? WHERE id=?", (new_ui, user["id"]))
            st.rerun()
        if st.button(t["logout"], use_container_width=True):
            st.session_state.clear()
            st.rerun()

    all_courses = courses()
    if "active_lesson" in st.session_state:
        active = st.session_state.active_lesson
        course = next((c for c in all_courses if c["id"] == active["course_id"]), None)
        lesson = next((l for l in course["lessons"] if l.get("id") == active["lesson_id"]), None) if course else None
        if course and lesson:
            questions = lesson.get("questions", [])
            idx = st.session_state.get("question_index", 0)
            if idx >= len(questions):
                finish_lesson(user["id"], course["id"], lesson["id"])
                st.balloons()
                st.markdown(f"## 🎉 {t['finish']}")
                st.write(t["finish_body"])
                st.markdown(f"### 🔥 {get_user(user['id'])['streak']} {t['streak']}")
                if st.button(t["back"], type="primary"):
                    for key in ("active_lesson", "question_index", "lesson_token"):
                        st.session_state.pop(key, None)
                    st.rerun()
                return
            render_question(course, questions[idx], idx + 1, len(questions), t, user["id"])
            return
        st.session_state.pop("active_lesson", None)

    st.markdown(f"## {t['welcome']}, {user['username']}!")
    st.markdown(f'<div class="stats">⭐ {user["xp"]} {t["xp"]} &nbsp; · &nbsp; 🔥 {user["streak"]} {t["streak"]}</div>', unsafe_allow_html=True)
    st.write("")
    if not all_courses:
        st.info(t["no_courses"])
        return
    options = [c for c in all_courses if c.get("ui_language", "en") == ui] or all_courses
    labels = [f"{c.get('title', c['id'])} · {c.get('from','?').upper()} → {c.get('to','?').upper()}" for c in options]
    picked = st.selectbox(t["choose_course"], range(len(options)), format_func=lambda i: labels[i])
    course = options[picked]
    lessons = course["lessons"]
    done = completed_ids(user["id"], course["id"])
    st.caption(course.get("description", ""))
    if not lessons:
        st.info(t["no_lessons"])
        return
    st.markdown(f"### {t['learn']} · {course.get('title', course['id'])}")
    for lesson in lessons:
        lid = str(lesson.get("id", "lesson"))
        is_done = lid in done
        with st.container(border=True):
            left, right = st.columns([4, 1])
            with left:
                st.markdown(f"**{t['lesson']} {lesson.get('title', lid)}**" + (" ✅" if is_done else ""))
                st.caption(lesson.get("description", f"{len(lesson.get('questions', []))} questions"))
            with right:
                if st.button(t["continue"] if is_done else t["start"], key=f"open_{course['id']}_{lid}", type="primary", use_container_width=True):
                    st.session_state.active_lesson = {"course_id":course["id"], "lesson_id":lid}
                    st.session_state.question_index = 0
                    st.session_state.lesson_token = secrets.token_hex(4)
                    st.rerun()
    st.caption(f"{len(done)} {t['lessons_done']}")


init_db()
if "user" not in st.session_state:
    render_auth()
else:
    render_app()
