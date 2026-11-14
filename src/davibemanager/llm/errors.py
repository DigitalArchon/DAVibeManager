"""A provider's error in words, as the openai and Anthropic libraries' errors carry them.

openai 3.38 and later put only the body's "message" in an error's text ("Error code: 400 - This
request is too long for the model's context window.") and nothing of a body that isn't JSON
("Error code: 400"): the code ("context_length_exceeded") and a plain-text answer ("prompt is too
long: … tokens > … maximum") are in `.body` alone. 3.37 and earlier wrote the whole body into the
text, uncut; the Anthropic library still does. So every reader of an error's words goes through
here: error_words to match them, shown_error to show them.
"""

from __future__ import annotations

import json
import re

from ..safety.hidden import visible

# of a provider's own words shown with an error: one line, as tee's and Private Mode's relay_said cut theirs
SHOWN_WORDS = 300


def error_words(err: BaseException | str) -> str:
    """Everything an error says, to match words in: its text, and the body the provider sent with it."""
    text = str(err)
    body = None if isinstance(err, str) else getattr(err, "body", None)
    if body is None or body == "":
        return text
    return f"{text}\n{body}"


def _sdk_error(err: BaseException) -> bool:
    from openai import APIError

    try:
        from anthropic import APIError as AnthropicError
    except ImportError:          # an app without the Anthropic library
        AnthropicError = APIError
    return isinstance(err, (APIError, AnthropicError))


def said(text: str, limit: int = SHOWN_WORDS) -> str:
    """A provider's words as shown: one line, without what can't be seen (safety/hidden.py), cut to `limit`."""
    return " ".join(visible(re.sub(r"[\x00-\x1f\x7f\x85\u2028\u2029]", " ", text[:4096])).split())[:limit]


def shown_error(err: BaseException) -> str:
    """An error as the technician is shown it. A library's: its status and the provider's message, then whatever
    else the provider answered (a plain-text body, a JSON body's other fields), labelled as the provider's, each on
    one line and cut to SHOWN_WORDS; the same whichever openai version wrote it (3.37 put the whole body, uncut, in
    the text). Any other error: its text, as it was."""
    if not _sdk_error(err):
        return str(err)
    body = err.body
    status = getattr(err, "status_code", None)
    message = body.get("message") if isinstance(body, dict) else None
    if isinstance(status, int):
        text = f"Error code: {status}" + (f" - {said(message)}" if isinstance(message, str) and message else "")
    else:
        text = said(str(err))                    # an error the stream carried: its text is the provider's message
    rest = {k: v for k, v in body.items() if k != "message" and v not in (None, "", [], {})} \
        if isinstance(body, dict) else body
    if rest not in (None, "", {}, []):
        words = json.dumps(rest, ensure_ascii=False, default=str) if isinstance(rest, (dict, list)) else str(rest)
        text += f" (the provider said: {said(words)})"
    return text
