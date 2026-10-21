"""A read-only rich-text pane whose copy behaviour is plain text with
real newlines in it.

Reported from an engagement: a Lucky 13 finding lists the CBC cipher
suites one per line on screen, and pasting it into a report produced one
long line.

Two separate Qt behaviours cause that, and both have to be undone:

  * ``QTextCursor.selectedText()`` does not return "\\n". It returns
    U+2029 PARAGRAPH SEPARATOR between blocks and U+2028 LINE SEPARATOR
    for a ``<br>``. Most editors treat neither as a line break, so the
    text arrives as one line. Findings are rendered with ``<br>``
    throughout, which is why this bit most of all.

  * Qt also puts a ``text/html`` flavour on the clipboard, serialised by
    its own writer. Some paste targets render that as literal markup,
    which is how a copied finding becomes a wall of ``<span style=…>``.

widgets/console.py already solved this for the console — and only for
the console, and only for U+2029. The findings and Active Scan detail
panes are the ones a tester actually copies out of for a report, and
they were plain ``QTextEdit``. Rather than a third copy of the fix, it
lives here once.
"""

from PyQt6.QtCore import QMimeData
from PyQt6.QtWidgets import QTextEdit

#: What Qt hands back in place of a newline.
PARAGRAPH_SEPARATOR = " "
LINE_SEPARATOR = " "


def as_plain_text(selected):
    """``selectedText()`` output with real newlines in it."""
    return (str(selected or "")
            .replace(PARAGRAPH_SEPARATOR, "\n")
            .replace(LINE_SEPARATOR, "\n")
            # &nbsp; is used to keep column alignment on screen; pasted
            # into a report it is an invisible character that breaks
            # search and sometimes line wrapping.
            .replace("\u00a0", " "))


class PlainCopyTextEdit(QTextEdit):
    """A QTextEdit that copies what it looks like."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)

    def createMimeDataFromSelection(self):
        mime = QMimeData()
        mime.setText(as_plain_text(self.textCursor().selectedText()))
        return mime
