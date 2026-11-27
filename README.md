# Igor

Igor is a playable Streamlit language-learning app with a tortoise mascot, accounts, XP, streaks, lesson progress, and simple JSON course files.

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Course format

Add `courses/<course-id>/course.json`. The JSON syntax is intentionally small:

- `multiple_choice`: prompt, 3 options, answer
- `write`: prompt, answer, optional accepted answers
- `word_bank`: prompt, words, answer
- `listen`: prompt, options, answer
- `gap`: prompt, sentence, answer
- `match`: prompt and left/right pairs
- `audio_match`: prompt and pairs with `left`, `right`, and optional `audio_text`

The `ui_language` field localizes the app: `en` or `es`. Place optional audio clips in `courses/<course-id>/audio/`. An audio question may specify `audio`; otherwise the app derives a matching filename from the text. Missing audio is safe.
