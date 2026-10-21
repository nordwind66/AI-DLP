"""CJK-aware word splitter for GLiNER.

GLiNER's default splitter (gliner/data_processing/tokenizer.py: WhitespaceTokenSplitter, regex
``\\w+(?:[-_]\\w+)*|\\S``) treats a run of Han characters as ONE word, so "张三的手机号是13800138000" is a single
token and the model can only label it as a whole (the engulfing spans measured in docs/m1_gliner_verify.txt).
This splitter makes every Han character its own token and keeps Latin words / numbers / e-mail-like runs intact.
Offsets are character offsets into the original text, as GLiNER expects.
"""
import re

_HAN = "㐀-䶿一-鿿豈-﫿"
_PATTERN = re.compile(
    rf"[{_HAN}]"                                  # one Han character per token
    rf"|(?:(?![{_HAN}])\w)+(?:[-_.@](?:(?![{_HAN}])\w)+)*"   # latin/digit word, keeps a-b_c.d@e together
    r"|\S"
)


class CjkTokenSplitter:
    def __call__(self, text):
        for m in _PATTERN.finditer(text):
            yield m.group(), m.start(), m.end()


def install(model):
    """Replace the words splitter of a loaded GLiNER model in place."""
    model.data_processor.words_splitter = CjkTokenSplitter()
    return model
