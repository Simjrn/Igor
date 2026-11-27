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
COURSE_LOAD_ERRORS: list[str] = []
TEXT = {
    "en": {"tagline":"Small steps. Strong shell.","learn":"Learn","log_in":"Log in","sign_up":"Create account","username":"Username","password":"Password","logout":"Log out","welcome":"Welcome back","choose_course":"Choose your course","lesson":"Lesson","start":"Start lesson","continue":"Continue","xp":"XP","streak":"day streak","lessons_done":"lessons completed","check":"Check answer","next":"Continue","correct":"Nice work!","incorrect":"Not quite — try again.","finish":"Lesson complete!","finish_body":"You kept moving. Every little step counts.","back":"Back to lessons","no_courses":"No playable courses found. Add a course JSON file under the courses folder.","audio_missing":"Audio isn't available for this question yet.","pick":"Choose an answer","write_here":"Type your translation","wordbank_hint":"Tap words to build your answer.","empty":"Choose an option","already":"That username is already taken.","bad_login":"Username or password is incorrect.","create_first":"Create an account to save your XP, streak, and lesson progress.","language":"Interface language","question_of":"Question","correct_answer":"A good answer:","no_lessons":"This course has no lessons yet.","unit":"UNIT","locked":"Complete the lessons above to unlock this one.","notes":"📘 Unit notes","course_errors":"Some course files could not be loaded"},
    "es": {"tagline":"Pasos pequeños. Caparazón fuerte.","learn":"Aprender","log_in":"Iniciar sesión","sign_up":"Crear cuenta","username":"Usuario","password":"Contraseña","logout":"Cerrar sesión","welcome":"¡Qué bueno verte!","choose_course":"Elige tu curso","lesson":"Lección","start":"Empezar lección","continue":"Continuar","xp":"XP","streak":"días seguidos","lessons_done":"lecciones completadas","check":"Comprobar","next":"Continuar","correct":"¡Muy bien!","incorrect":"Casi — inténtalo de nuevo.","finish":"¡Lección completada!","finish_body":"Seguiste avanzando. Cada paso cuenta.","back":"Volver a las lecciones","no_courses":"No se encontraron cursos jugables. Añade un archivo JSON en la carpeta courses.","audio_missing":"El audio aún no está disponible para esta pregunta.","pick":"Elige una respuesta","write_here":"Escribe tu traducción","wordbank_hint":"Pulsa palabras para formar tu respuesta.","empty":"Elige una opción","already":"Ese usuario ya existe.","bad_login":"El usuario o la contraseña no son correctos.","create_first":"Crea una cuenta para guardar tus XP, racha y progreso.","language":"Idioma de la interfaz","question_of":"Pregunta","correct_answer":"Una respuesta válida:","no_lessons":"Este curso todavía no tiene lecciones.","unit":"UNIDAD","locked":"Completa las lecciones anteriores para desbloquear esta.","notes":"📘 Notas de la unidad","course_errors":"No se pudieron cargar algunos archivos de curso"},
}

st.set_page_config(page_title="Igor · Language learning", page_icon="🐢", layout="centered")
st.html("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800;900&display=swap');
:root { --igor:#27734f; --igor-dark:#174b35; }
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
            salt BLOB NOT NULL, password_hash BLOB NOT NULL,
            ui_language TEXT NOT NULL DEFAULT 'en', xp INTEGER NOT NULL DEFAULT 0,
            streak INTEGER NOT NULL DEFAULT 0, last_active TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS completed_lessons (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            course_id TEXT NOT NULL, lesson_id TEXT NOT NULL, completed_at TEXT NOT NULL,
            PRIMARY KEY(user_id, course_id, lesson_id)
        );
        """)


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)


def register(username: str, password: str, language: str) -> bool:
    name = username.strip()
    if len(name) < 3 or len(name) > 24 or not re.fullmatch(r"[\w.-]+", name, flags=re.UNICODE) or len(password) < 8:
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
    """Discover valid course JSON files recursively and report malformed files."""
    found: list[dict[str, Any]] = []
    COURSE_LOAD_ERRORS.clear()
    if not COURSES_DIR.is_dir():
        COURSE_LOAD_ERRORS.append(f"Missing folder: {COURSES_DIR}")
        return found

    for path in sorted(COURSES_DIR.rglob("course.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(data, dict):
                raise ValueError("top level must be a JSON object")
            data["_path"] = path.parent
            data["id"] = str(data.get("id") or path.parent.name)
            if not isinstance(data.get("units"), list):
                lessons = data.get("lessons", [])
                if not isinstance(lessons, list):
                    raise ValueError("expected a 'units' or 'lessons' list")
                data["units"] = [{"id":"course-lessons", "title":data.get("title", path.parent.name), "topic":data.get("description", ""), "lessons":lessons}]
            for i, unit in enumerate(data["units"]):
                if not isinstance(unit, dict):
                    raise ValueError(f"unit {i + 1} must be an object")
                if not isinstance(unit.get("lessons", []), list):
                    raise ValueError(f"lessons in unit {i + 1} must be a list")
            found.append(data)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            COURSE_LOAD_ERRORS.append(f"{path.relative_to(COURSES_DIR)}: {exc}")
    return found


def normalize(text: Any) -> str:
    value = unicodedata.normalize("NFKD", str(text or "").casefold().strip())
    value = "".join(c for c in value if not unicodedata.combining(c))
    return re.sub(r"[^\w]+", " ", value, flags=re.UNICODE).strip()


def audio_path(course: dict, question: dict) -> Path | None:
    folder = course["_path"] / "audio"
    if not folder.is_dir():
        folder = course["_path"] / "audios"
    if not folder.is_dir():
        return None
    candidates = [str(question["audio"])] if question.get("audio") else []
    for key in (question.get("text"), question.get("prompt"), question.get("answer"), question.get("audio_text")):
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
            fmt = {".mp3":"audio/mpeg", ".wav":"audio/wav", ".ogg":"audio/ogg", ".m4a":"audio/mp4", ".webm":"audio/webm"}.get(path.suffix.lower())
            st.audio(path.read_bytes(), format=fmt)
            return
        except OSError:
            pass
    st.caption(t["audio_missing"])


def feedback_sound(correct: bool, key: str) -> None:
    sound_id = re.sub(r"[^a-zA-Z0-9_-]", "", key)
    frequencies = "[660,880]" if correct else "[220,165]"
    wave = "sine" if correct else "triangle"
    st.html(f'''<div id="igor-sound-{sound_id}" aria-hidden="true"></div><script>
    (() => {{ try {{ const C=window.AudioContext||window.webkitAudioContext; const c=new C();
      [{frequencies}].forEach((hz,i)=>{{const o=c.createOscillator(),g=c.createGain();o.type="{wave}";o.frequency.value=hz;
      g.gain.setValueAtTime(.0001,c.currentTime+i*.13);g.gain.exponentialRampToValueAtTime(.12,c.currentTime+i*.13+.02);
      g.gain.exponentialRampToValueAtTime(.0001,c.currentTime+i*.13+.19);o.connect(g);g.connect(c.destination);
      o.start(c.currentTime+i*.13);o.stop(c.currentTime+i*.13+.2);}});setTimeout(()=>c.close(),550);
    }} catch(e) {{}} }})();</script>''', unsafe_allow_javascript=True)


def completed_ids(user_id: int, course_id: str) -> set[str]:
    with db() as conn:
        rows = conn.execute("SELECT lesson_id FROM completed_lessons WHERE user_id=? AND course_id=?", (user_id, course_id)).fetchall()
    return {row[0] for row in rows}


def award_xp(user_id: int) -> None:
    with db() as conn:
        conn.execute("UPDATE users SET xp=xp+5 WHERE id=?", (user_id,))


def finish_lesson(user_id: int, course_id: str, lesson_id: str) -> None:
    today = date.today()
    with db() as conn:
        user = conn.execute("SELECT streak,last_active FROM users WHERE id=?", (user_id,)).fetchone()
        already = conn.execute("SELECT 1 FROM completed_lessons WHERE user_id=? AND course_id=? AND lesson_id=?", (user_id, course_id, lesson_id)).fetchone()
        if already:
            return
        previous = date.fromisoformat(user["last_active"]) if user["last_active"] else None
        streak = user["streak"] if previous == today else user["streak"] + 1 if previous == today - timedelta(days=1) else 1
        conn.execute("UPDATE users SET streak=?,last_active=? WHERE id=?", (streak, today.isoformat(), user_id))
        conn.execute("INSERT INTO completed_lessons(user_id,course_id,lesson_id,completed_at) VALUES(?,?,?,?)",
                     (user_id, course_id, lesson_id, datetime.utcnow().isoformat()))


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


def render_question(course: dict, question: dict, number: int, total: int, t: dict, user_id: int) -> None:
    qtype = question.get("type", "multiple_choice")
    st.progress(number / max(total, 1))
    st.markdown(f'<div class="question-label">{t["question_of"]} {number} / {total}</div>', unsafe_allow_html=True)
    st.markdown(f"## {question.get('prompt', question.get('text', 'Translate this'))}")
    qkey = f"answer_{st.session_state.lesson_token}_{number}"
    checked_key = qkey + "_checked"
    if checked_key not in st.session_state:
        st.session_state[checked_key] = None

    with st.form("question_form_" + qkey):
        value: Any = None
        if qtype in ("multiple_choice", "listen"):
            if qtype == "listen":
                audio_widget(course, question, t)
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
            options = [pair.get("right", "") for pair in pairs]
            for i, pair in enumerate(pairs):
                left = pair.get("left", "")
                if qtype == "audio_match":
                    audio_widget(course, {"audio":pair.get("audio"), "text":pair.get("audio_text", left)}, t)
                value[left] = st.selectbox(f"{left} →", [t["empty"]] + options, key=f"{qkey}_{i}")
        else:
            st.error(f"Unsupported question type: {qtype}")
        submitted = st.form_submit_button(t["check"], type="primary", use_container_width=True)

    if submitted:
        if qtype in ("multiple_choice", "listen", "write", "word_bank", "gap"):
            accepted = question.get("accepted", [question.get("answer", "")])
            if not isinstance(accepted, list):
                accepted = [accepted]
            is_correct = normalize(value) in {normalize(item) for item in accepted}
        elif qtype in ("match", "audio_match"):
            pairs = question.get("pairs", [])
            is_correct = bool(pairs) and all(value.get(pair["left"]) == pair["right"] for pair in pairs)
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
        sound_key = qkey + "_correct"
        if st.session_state.get("last_sound") != sound_key:
            st.session_state.last_sound = sound_key
            feedback_sound(True, sound_key)
        if st.button(t["next"], key="next_" + qkey, type="primary", use_container_width=True):
            st.session_state.question_index += 1
            st.rerun()
    elif result is False:
        st.error(t["incorrect"])
        sound_key = qkey + "_incorrect"
        if st.session_state.get("last_sound") != sound_key:
            st.session_state.last_sound = sound_key
            feedback_sound(False, sound_key)
        if qtype in ("write", "word_bank", "gap"):
            st.caption(f"{t['correct_answer']} {question.get('answer', '')}")
        if st.button(t["continue"], key="retry_" + qkey, use_container_width=True):
            st.session_state[checked_key] = None
            st.session_state.pop(qkey, None)
            for i in range(len(question.get("pairs", []))):
                st.session_state.pop(f"{qkey}_{i}", None)
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
        st.markdown(f"**{user['xp']} {t['xp']}** · **🔥 {user['streak']} {t['streak']}**")
        new_ui = st.selectbox(t["language"], ["en", "es"], index=0 if ui == "en" else 1, format_func=lambda x: "English" if x == "en" else "Español")
        if new_ui != ui:
            with db() as conn:
                conn.execute("UPDATE users SET ui_language=? WHERE id=?", (new_ui, user["id"]))
            st.rerun()
        if st.button(t["logout"], use_container_width=True):
            st.session_state.clear()
            st.rerun()

    all_courses = courses()
    if COURSE_LOAD_ERRORS:
        with st.expander(t["course_errors"]):
            for error in COURSE_LOAD_ERRORS:
                st.warning(error)

    if "active_lesson" in st.session_state:
        active = st.session_state.active_lesson
        course = next((item for item in all_courses if item["id"] == active["course_id"]), None)
        lesson = next((lesson for unit in course["units"] for lesson in unit.get("lessons", []) if lesson.get("id") == active["lesson_id"]), None) if course else None
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
                    for key in ("active_lesson", "question_index", "lesson_token", "last_sound"):
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

    labels = [f"{item.get('title', item['id'])} · {item.get('from', '?').upper()} → {item.get('to', '?').upper()}" for item in all_courses]
    course = all_courses[st.selectbox(t["choose_course"], range(len(all_courses)), format_func=lambda i: labels[i])]
    st.caption(course.get("description", ""))
    done = completed_ids(user["id"], course["id"])
    units = course.get("units", [])
    if not units:
        st.info(t["no_lessons"])
        return

    previous_done = True
    lesson_count = 0
    for unit_index, unit in enumerate(units):
        st.markdown("<div style='height:20px'></div><hr style='border:0;border-top:2px solid #dcebe0;margin:20px 0 24px'>", unsafe_allow_html=True)
        st.markdown(f"### 🐢 {t['unit']} {unit_index + 1} · {unit.get('title', 'Unit')}")
        if unit.get("topic"):
            st.caption(unit["topic"])
        notes = unit.get("notes", "")
        if notes:
            with st.expander(t["notes"], expanded=False):
                st.markdown(notes)
        for lesson in unit.get("lessons", []):
            lesson_id = str(lesson.get("id", "lesson"))
            is_done = lesson_id in done
            can_start = previous_done
            lesson_count += 1
            with st.container(border=True):
                left, right = st.columns([4, 1])
                with left:
                    st.markdown(f"**{t['lesson']} {lesson.get('title', lesson_id)}**" + (" ✅" if is_done else ""))
                    detail = lesson.get("description", f"{len(lesson.get('questions', []))} questions")
                    difficulty = lesson.get("difficulty")
                    st.caption(f"{detail}" + (f" · {difficulty}" if difficulty else ""))
                    if not can_start:
                        st.caption("🔒 " + t["locked"])
                with right:
                    label = t["continue"] if is_done else t["start"]
                    if st.button(label, key=f"open_{course['id']}_{lesson_id}", type="primary", use_container_width=True, disabled=not can_start):
                        st.session_state.active_lesson = {"course_id":course["id"], "lesson_id":lesson_id}
                        st.session_state.question_index = 0
                        st.session_state.lesson_token = secrets.token_hex(4)
                        st.session_state.pop("last_sound", None)
                        st.rerun()
            previous_done = previous_done and is_done
    st.caption(f"{len(done)} / {lesson_count} {t['lessons_done']}")


init_db()
if "user" not in st.session_state:
    render_auth()
else:
    render_app()
