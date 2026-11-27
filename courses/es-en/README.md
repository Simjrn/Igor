# Spanish for English speakers (`es-en`)

This course is deliberately separate from the app code: all units, lessons, and questions are in `course.json`. You can copy the folder, change the course metadata, and write another course as JSON.

## Structure

- `units` divides the course into topic-based sections, with a clear gap between each unit.
- Each unit has an `id`, a learner-facing `title`, a short `topic` note, and ordered `lessons`.
- Lessons use `id`, `title`, `difficulty`, `description`, and `questions`.
- Questions are ordered JSON objects. See the first unit for examples of multiple choice, writing, word bank, listening, gap fill, and matching.
- Difficulty rises from greetings and short words to café orders, longer everyday sentences, then practical travel conversations.
- Lessons unlock in order. Complete the previous lesson to unlock the next; all lessons in a unit unlock before the next unit begins.

Question types: `multiple_choice`, `write`, `word_bank`, `listen`, `gap`, `match`, and `audio_match`.

Optional course audio belongs in this folder's `audio/` subfolder. Set an `audio` filename explicitly on a question/pair, or name the clip from the phrase (for example `hola.mp3`). Audio is optional; missing clips show a gentle note and don't block lessons.
