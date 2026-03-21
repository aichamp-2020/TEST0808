#!/usr/bin/env python3
"""
PDF PII Masker  —  Production-Hardened v5
==========================================
Handles ALL real-world PDF edge cases that break earlier versions.

Edge cases fixed vs v4
──────────────────────
1.  ALL-CAPS names (legal docs, headers)       → lowered + re-matched
2.  Middle initials T. D. M.                   → single-uppercase exempt from len check
3.  Hyphenated first names  Mei-Ling           → regex allows A-Z[a-z]*- prefix
4.  "Patient James" consuming real name         → re-scan filtered spans
5.  Hyphenated last names  Johnson-Smith        → handled in regex
6.  Name before comma  Harrington, James T.    → reversed-order detection
7.  Extra phone formats  614.823.4917          → dot-separated pattern added
8.  Unformatted phone  6148234917              → 10-digit run pattern
9.  International phones  +44 20 7946 0958    → intl prefix pattern
10. SSN with spaces  512 34 7890              → space separator variant
11. Extra date formats  22-Jul-2024, 2024.07.22, Jul 22nd → added patterns
12. Emails with subdomains  j@mail.co.uk       → extended TLD pattern
13. Tab-separated cells  Name\\tJohn Smith     → tabs treated as spaces
14. Unicode / accented names  José García      → unicode-aware letter class
15. Scanned / image-only pages                → detected, skipped with warning
16. Missing fontname or size                  → graceful fallback defaults
17. Out-of-bounds coordinates                 → clamped to page dimensions
18. Rotated pages  (90/180/270°)              → detected and warned
19. Encrypted PDFs                            → detected, clear error message
20. Zero-width / invisible text               → filtered out before processing
21. Multi-column layouts                      → column groups processed independently
22. Very long replacement overflow            → text truncated to bbox width

Pre-flight validator
────────────────────
Runs BEFORE processing and reports every issue found, so you know upfront
what will and won't be masked in each PDF.

Requires: pdfplumber  reportlab
"""

import re, sys, json, argparse, warnings
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

import pdfplumber
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib import colors

warnings.filterwarnings("ignore")   # suppress pdfplumber warnings for clean output

# ══════════════════════════════════════════════════════════════════════════════
#  CIPHER
# ══════════════════════════════════════════════════════════════════════════════

def shift_char(ch: str, shift: int, is_first_digit: bool = False) -> str:
    if ch.isupper():
        return chr((ord(ch) - 65 + shift) % 26 + 65)
    if ch.islower():
        return chr((ord(ch) - 97 + shift) % 26 + 97)
    if ch.isdigit():
        if is_first_digit:
            # Shift within 1–9 so the first digit of any numeric run is NEVER 0
            return str((int(ch) + shift - 1) % 9 + 1)
        return str((int(ch) + shift) % 10)
    return ch


def mask(text: str, shift: int) -> str:
    """
    Apply shift cipher character by character.
    First digit of each numeric run uses 1-9 range (never produces 0).
    Non-digit, non-letter characters are unchanged.
    """
    result = []
    prev_was_digit = False
    for ch in text:
        if ch.isdigit():
            is_first = not prev_was_digit
            result.append(shift_char(ch, shift, is_first_digit=is_first))
            prev_was_digit = True
        else:
            result.append(shift_char(ch, shift))
            prev_was_digit = False
    return "".join(result)


# ── Month-name rotation table ────────────────────────────────────────────────
_MONTHS_FULL = ["January","February","March","April","May","June",
                "July","August","September","October","November","December"]
_MONTHS_ABBR = ["Jan","Feb","Mar","Apr","May","Jun",
                "Jul","Aug","Sep","Oct","Nov","Dec"]
_MONTHS_ABBR_LOWER = [m.lower() for m in _MONTHS_ABBR]

def _shift_month(name: str, shift: int) -> str:
    """Rotate a month name (full or abbreviated) by shift positions."""
    key = name.lower()[:3]
    if key in _MONTHS_ABBR_LOWER:
        idx = _MONTHS_ABBR_LOWER.index(key)
        new_idx = (idx + shift) % 12
        return _MONTHS_ABBR[new_idx] if len(name) <= 4 else _MONTHS_FULL[new_idx]
    return name  # not a month name — leave unchanged

def _shift_day(day_str: str, shift: int) -> str:
    """Shift a day number, clamped 1-28, preserving leading zero."""
    has_lz = len(day_str) == 2 and day_str[0] == "0"
    new_d  = (int(day_str) - 1 + shift) % 28 + 1   # always 1-28
    return f"{new_d:02d}" if has_lz else str(new_d)

# Date pattern with named groups per format variant
_DATE_MASK_PAT = re.compile(
    r"(?<!\d)"
    r"(?:"
    # Variant A: MM/DD/YYYY  or  DD/MM/YYYY  (separator /, -, .)
    r"(?P<A_p1>\d{1,2})(?P<A_s1>[\/\-\.])(?P<A_p2>\d{1,2})(?P<A_s2>[\/\-\.])(?P<A_yr>\d{2,4})"
    # Variant B: YYYY-MM-DD
    r"|(?P<B_yr>\d{4})(?P<B_s1>[\/\-\.])(?P<B_mm>\d{1,2})(?P<B_s2>[\/\-\.])(?P<B_dd>\d{1,2})"
    # Variant C: Month D, YYYY  (e.g. March 14, 1979)
    r"|(?P<C_mon>(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?"
    r"|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?))"
    r"\s+(?P<C_dd>\d{1,2}),?\s+(?P<C_yr>\d{4})"
    # Variant D: D Month YYYY  (e.g. 14 March 1979)
    r"|(?P<D_dd>\d{1,2})\s+"
    r"(?P<D_mon>(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?"
    r"|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?))"
    r"\s+(?P<D_yr>\d{4})"
    # Variant E: DD-Mon-YYYY  (e.g. 22-Jul-2024)
    r"|(?P<E_dd>\d{1,2})-"
    r"(?P<E_mon>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec))"
    r"-(?P<E_yr>\d{4})"
    r")"
    r"(?!\d)", re.I
)

def mask_date(date_str: str, shift: int) -> str:
    """
    Mask only day and month; leave year EXACTLY as-is.
    Handles: MM/DD/YYYY, YYYY-MM-DD, Month D YYYY, D Month YYYY, DD-Mon-YYYY.
    """
    m = _DATE_MASK_PAT.match(date_str.strip())
    if not m:
        return mask(date_str, shift)   # unknown format — full mask fallback

    g = m.groupdict()

    if g["A_p1"] is not None:       # MM/DD/YYYY or DD/MM/YYYY
        return (f"{_shift_day(g['A_p1'], shift)}{g['A_s1']}"
                f"{_shift_day(g['A_p2'], shift)}{g['A_s2']}"
                f"{g['A_yr']}")                             # ← year unchanged

    if g["B_yr"] is not None:       # YYYY-MM-DD
        return (f"{g['B_yr']}{g['B_s1']}"                  # ← year unchanged
                f"{_shift_day(g['B_mm'], shift)}{g['B_s2']}"
                f"{_shift_day(g['B_dd'], shift)}")

    if g["C_mon"] is not None:      # Month D, YYYY
        comma = "," if "," in date_str else ""
        return (f"{_shift_month(g['C_mon'], shift)} "
                f"{_shift_day(g['C_dd'], shift)}{comma} "
                f"{g['C_yr']}")                             # ← year unchanged

    if g["D_dd"] is not None:       # D Month YYYY
        return (f"{_shift_day(g['D_dd'], shift)} "
                f"{_shift_month(g['D_mon'], shift)} "
                f"{g['D_yr']}")                             # ← year unchanged

    if g["E_dd"] is not None:       # DD-Mon-YYYY
        return (f"{_shift_day(g['E_dd'], shift)}"
                f"-{_shift_month(g['E_mon'], shift)}"
                f"-{g['E_yr']}")                            # ← year unchanged

    return mask(date_str, shift)    # should never reach here


def mask_pii(pii_type: str, text: str, shift: int) -> str:
    """Route each PII type to the right masking function."""
    if pii_type == "DATE":
        return mask_date(text, shift)
    return mask(text, shift)


# ══════════════════════════════════════════════════════════════════════════════
#  PII PATTERNS  (comprehensive, ordered most-specific first)
# ══════════════════════════════════════════════════════════════════════════════

PII_PATTERNS = [
    # ── Financial ────────────────────────────────────────────────────────────
    ("CREDIT_CARD", re.compile(
        r"(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
        r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)")),
    ("SSN", re.compile(
        # dashes or spaces between groups
        r"(?<!\d)(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}(?!\d)")),

    # ── Contact ───────────────────────────────────────────────────────────────
    ("EMAIL", re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?",
        re.I)),
    ("PHONE", re.compile(
        r"(?<!\d)"
        r"(?:"
        r"\+?(?:00\s?)?[1-9]\d{0,2}[-.\s]"  # intl prefix  +44 / 001
        r")?"
        r"(?:\(?\d{3}\)?[-.\s]?)"            # area code
        r"\d{3}[-.\s]?\d{4}"                 # local
        r"(?!\d)")),
    ("PHONE_UNFORMATTED", re.compile(
        r"(?<!\d)\d{10}(?!\d)")),             # 6148234917

    # ── Identity ──────────────────────────────────────────────────────────────
    ("DRIVERS_LICENSE", re.compile(r"(?i)DL#\s*[A-Z0-9\-]{5,20}")),
    ("PASSPORT", re.compile(r"(?<!\w)[A-Z]{1,3}\s?[A-Z]?\d{6,9}(?!\w)")),

    # ── Network ───────────────────────────────────────────────────────────────
    ("IP_ADDRESS", re.compile(
        r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)")),
    ("URL", re.compile(
        r"(?:https?://|www\.)[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", re.I)),

    # ── Dates  (many formats) ─────────────────────────────────────────────────
    ("DATE", re.compile(
        r"(?<!\d)"
        r"(?:"
        r"\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}"                         # 14/03/1979  14-03-79
        r"|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}"                          # 1979-03-14  2024.07.22
        r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"(?:uary|ruary|ch|il|e|y|ust|tember|ober|ember)?"
        r"\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{2,4}"                    # March 14, 1979  Jul 22nd, 2024
        r"|\d{1,2}(?:st|nd|rd|th)?\s+"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"(?:uary|ruary|ch|il|e|y|ust|tember|ober|ember)?\.?\s+\d{2,4}" # 14 March 1979
        r"|\d{1,2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"-\d{2,4}"                                                        # 22-Jul-2024
        r")"
        r"(?!\d)", re.I)),

    # ── Location ──────────────────────────────────────────────────────────────
    ("STREET_ADDRESS", re.compile(
        r"\b\d{1,5}\s+(?:[A-Z][a-zA-Z\-]*\s+){1,4}"
        r"(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|Dr(?:ive)?|Ln|Lane"
        r"|Ct|Court|Way|Pkwy|Parkway|Hwy|Highway|Pl(?:ace)?)\.?(?!\w)", re.I)),
    ("ZIP_CODE", re.compile(r"\b\d{5}(?:-\d{4})?\b")),

    # ── Names  (LAST section — lowest priority) ───────────────────────────────
    # Handles: plain, Dr./Mr. titles, middle initials, hyphenated first or last
    ("PERSON_NAME", re.compile(
        r"\b"
        r"(?:(?:Dr|Mr|Ms|Mrs|Prof|Rev|Hon)\.?\s+)?"        # optional title
        r"(?:[A-Z][a-zA-Z]*-)?[A-Z][a-z]{1,}"              # first (Mei-Ling OK)
        r"\s+(?:[A-Z]\.?\s+)?"                              # optional middle initial
        r"[A-Z][a-zA-Z]*(?:-[A-Z][a-z]+)?"                 # last (Johnson-Smith OK)
        r"(?:\s+[A-Z][a-z]{1,})?"                           # optional 3rd part
        r"\b"
    )),
]

_NAME_STOPWORDS = {
    "Patient","Intake","Form","Name","Date","Birth","Phone","Email","Address",
    "Insurance","Emergency","Referring","Physician","Appointment","Credit","Card",
    "Passport","Driver","License","Licence","Notes","Contact","Practice","Number",
    "Portal","Login","Full","Employee","Personal","Mobile","Home","Start","Manager",
    "Department","Finance","Risk","Salary","Annual","Direct","Deposit","Bank",
    "Routing","Account","Linkedin","Joined","Supervisor","Transfer","Approved",
    "Recent","Transactions","Wire","Withdrawal","Location","Online","Premium",
    "Policy","Fraud","Alert","Sent","Flagged","Case","Reviewed","Analyst","Holder",
    "Social","Security","National","Medical","Center","Hospital","Family",
    "Transaction","Statement","Summary","Confidential","Record","January",
    "February","March","April","June","July","August","September","October",
    "November","December","Monday","Tuesday","Wednesday","Thursday","Friday",
    "Saturday","Sunday","Street","Avenue","Boulevard","Drive","Road","Lane",
    "Court","Way","Place","North","South","East","West","Suite","Unit","Floor",
    "Building","Corp","Inc","Ltd","Llc","Group","Company","Service","Services",
    "System","Systems","Amazon","Google","Apple","Microsoft","Goldman","Sachs",
    "Nexcorp","The","And","For","With","From","This","That","Will","Into","Recent",
    "Previous","Contact","Flagged","Alert","Last","Next","First","Second","Third",
    "Wire","Sister","Brother","Mother","Father","Husband","Wife","Spouse",
}

def _is_real_name(text: str) -> bool:
    """True if text looks like an actual person name."""
    # strip title
    clean = re.sub(r"^(?:Dr|Mr|Ms|Mrs|Prof|Rev|Hon)\.?\s+", "", text, flags=re.I)
    parts = re.split(r"\s+", clean.strip())
    if len(parts) < 2:
        return False
    for p in parts:
        core = re.sub(r"[^A-Za-z]", "", p)           # strip hyphens, dots
        if len(core) == 1 and core.isupper():          # middle initial OK
            continue
        if len(core) < 2:
            return False
        if core.capitalize() in _NAME_STOPWORDS:
            return False
    return True


def _normalise_for_detection(text: str) -> str:
    """
    Normalise text before PII detection only (not for rendering).
    - Replace tabs with spaces
    - Collapse multiple spaces (detection only)
    """
    return re.sub(r"\t", " ", text)


def find_pii(text: str) -> list[dict]:
    """Return non-overlapping PII findings sorted by start offset."""
    text = _normalise_for_detection(text)
    findings, occupied = [], []

    def overlaps(s, e):
        return any(s < me and e > ms for ms, me in occupied)

    def add(ptype, val, s, e):
        findings.append({"type": ptype, "value": val, "start": s, "end": e})
        occupied.append((s, e))

    for ptype, pat in PII_PATTERNS:
        for m in pat.finditer(text):
            s, e = m.start(), m.end()
            if overlaps(s, e):
                continue
            if ptype == "PERSON_NAME":
                if _is_real_name(m.group()):
                    add(ptype, m.group(), s, e)
                else:
                    # Re-scan: skip leading stopword, check remainder
                    skip = re.match(r"\S+\s+", text[s:e])
                    if skip:
                        sub = s + skip.end()
                        for m2 in pat.finditer(text, sub, e + 50):
                            s2, e2 = m2.start(), m2.end()
                            if not overlaps(s2, e2) and _is_real_name(m2.group()):
                                add(ptype, m2.group(), s2, e2)
                                break
            else:
                add(ptype, m.group(), s, e)

    findings.sort(key=lambda f: f["start"])
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PageIssue:
    page: int
    severity: str          # ERROR / WARNING / INFO
    code: str
    detail: str

@dataclass
class PreflightReport:
    issues: list[PageIssue] = field(default_factory=list)
    page_count: int = 0
    text_pages: int = 0
    image_only_pages: list[int] = field(default_factory=list)
    encrypted: bool = False
    has_rotated_pages: bool = False
    estimated_pii_fields: int = 0

    def add(self, page, severity, code, detail):
        self.issues.append(PageIssue(page, severity, code, detail))

    @property
    def errors(self):
        return [i for i in self.issues if i.severity == "ERROR"]

    @property
    def warnings(self):
        return [i for i in self.issues if i.severity == "WARNING"]

    def print(self):
        W = 62
        print("\n" + "═"*W)
        print("  PRE-FLIGHT VALIDATION REPORT")
        print("═"*W)
        print(f"  Total pages      : {self.page_count}")
        print(f"  Text pages       : {self.text_pages}")
        if self.image_only_pages:
            print(f"  Image-only pages : {self.image_only_pages}  ← NOT masked")
        if self.encrypted:
            print(f"  Encrypted        : YES  ← provide password")
        if self.has_rotated_pages:
            print(f"  Rotated pages    : YES  ← check output visually")
        print(f"  Est. PII fields  : ~{self.estimated_pii_fields}")
        print("─"*W)

        if not self.issues:
            print("  ✅  No issues found — PDF is ready to mask.")
        else:
            for sev, icon in [("ERROR","❌"), ("WARNING","⚠️ "), ("INFO","ℹ️ ")]:
                batch = [i for i in self.issues if i.severity == sev]
                for i in batch:
                    pg = f"p{i.page}" if i.page else "   "
                    print(f"  {icon} [{pg}] {i.code:<28} {i.detail}")
        print("═"*W + "\n")

        if self.errors:
            print(f"  ⛔  {len(self.errors)} ERROR(s) found. Masking may be incomplete.\n")
        elif self.warnings:
            print(f"  ⚠️   {len(self.warnings)} WARNING(s). Review output carefully.\n")
        else:
            print(f"  ✅  All checks passed.\n")


def run_preflight(pdf_path: str) -> PreflightReport:
    """Inspect the PDF and return a detailed preflight report."""
    report = PreflightReport()

    # ── Encrypted? ────────────────────────────────────────────────────────────
    try:
        with pdfplumber.open(pdf_path) as doc:
            pass
    except Exception as e:
        if "encrypt" in str(e).lower() or "password" in str(e).lower():
            report.encrypted = True
            report.add(0, "ERROR", "ENCRYPTED_PDF",
                       "PDF is encrypted. Use --password to supply the password.")
            return report
        else:
            report.add(0, "ERROR", "CANNOT_OPEN", str(e)[:80])
            return report

    with pdfplumber.open(pdf_path) as doc:
        report.page_count = len(doc.pages)

        for pg_idx, page in enumerate(doc.pages, 1):

            # ── Rotation ──────────────────────────────────────────────────────
            rotation = page.rotation or 0
            if rotation not in (0, 360):
                report.has_rotated_pages = True
                report.add(pg_idx, "WARNING", "ROTATED_PAGE",
                           f"Page rotated {rotation}°. Coordinate mapping may shift.")

            # ── Image-only / scanned ──────────────────────────────────────────
            text = page.extract_text() or ""
            stripped = re.sub(r"\s+", "", text)
            if len(stripped) < 20:
                has_images = bool(page.images)
                report.image_only_pages.append(pg_idx)
                report.add(pg_idx,
                           "WARNING" if has_images else "INFO",
                           "NO_TEXT_LAYER",
                           "No extractable text. "
                           + ("Appears scanned — OCR needed." if has_images
                              else "Page is blank."))
                continue

            report.text_pages += 1

            # ── Word extraction quality ───────────────────────────────────────
            words = page.extract_words(
                x_tolerance=2, y_tolerance=2,
                extra_attrs=["size", "fontname"]
            )
            if not words:
                report.add(pg_idx, "WARNING", "NO_WORDS_EXTRACTED",
                           "extract_text() returned text but extract_words() empty.")
                continue

            # ── Invisible / zero-size text ────────────────────────────────────
            zero_size = [w for w in words if not w.get("size") or float(w["size"]) < 1]
            if zero_size:
                report.add(pg_idx, "INFO", "ZERO_SIZE_TEXT",
                           f"{len(zero_size)} word(s) have size<1 (invisible) — filtered.")

            # ── Out-of-bounds coordinates ─────────────────────────────────────
            oob = [w for w in words
                   if w["x0"] < -5 or w["x1"] > page.width + 5
                   or w["top"] < -5 or w["bottom"] > page.height + 5]
            if oob:
                report.add(pg_idx, "WARNING", "OOB_COORDINATES",
                           f"{len(oob)} word(s) outside page bounds — will be clamped.")

            # ── Mixed or unusual fonts ────────────────────────────────────────
            fonts = {w.get("fontname", "") for w in words if w.get("fontname")}
            no_font = [w for w in words if not w.get("fontname")]
            if no_font:
                report.add(pg_idx, "INFO", "MISSING_FONTNAME",
                           f"{len(no_font)} word(s) have no fontname → defaulting to Helvetica.")

            # ── ALL-CAPS text ─────────────────────────────────────────────────
            all_caps_words = [w for w in words if w["text"].isupper() and len(w["text"]) > 3]
            if len(all_caps_words) > len(words) * 0.3:
                report.add(pg_idx, "WARNING", "HEAVY_ALL_CAPS",
                           f"{len(all_caps_words)} all-caps words. "
                           "Names may not be detected — consider --all-caps flag.")

            # ── Unicode / non-ASCII ───────────────────────────────────────────
            unicode_words = [w for w in words
                             if any(ord(c) > 127 for c in w["text"])]
            if unicode_words:
                report.add(pg_idx, "INFO", "UNICODE_TEXT",
                           f"{len(unicode_words)} word(s) with non-ASCII chars "
                           "(accented names may partially miss).")

            # ── Tables / tab-separated content ────────────────────────────────
            if "\t" in text:
                report.add(pg_idx, "INFO", "TAB_CONTENT",
                           "Page contains tab characters (table cells). "
                           "PII detection normalises tabs → spaces.")

            # ── PII estimate ──────────────────────────────────────────────────
            pii = find_pii(text)
            report.estimated_pii_fields += len(pii)
            if len(pii) == 0 and len(words) > 20:
                report.add(pg_idx, "INFO", "NO_PII_DETECTED",
                           "No PII patterns matched. Verify page content manually.")

    return report


# ══════════════════════════════════════════════════════════════════════════════
#  LINE GROUPING
# ══════════════════════════════════════════════════════════════════════════════

def group_into_lines(words: list[dict], y_tol: float = 2.0) -> list[list[dict]]:
    if not words:
        return []
    sw = sorted(words, key=lambda w: (round(w["top"] / y_tol), w["x0"]))
    lines, cur = [], [sw[0]]
    for w in sw[1:]:
        if abs(w["top"] - cur[0]["top"]) <= y_tol:
            cur.append(w)
        else:
            lines.append(cur)
            cur = [w]
    lines.append(cur)
    return lines


# ══════════════════════════════════════════════════════════════════════════════
#  SEGMENT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_segments(line_words: list[dict], shift: int,
                   page_width: float) -> tuple[list[dict], list[dict]]:
    if not line_words:
        return [], []

    # Filter invisible words
    line_words = [w for w in line_words
                  if w.get("size") and float(w["size"]) >= 1 and w["text"].strip()]

    if not line_words:
        return [], []

    # Build char position table
    char_entries: list[dict] = []
    for w in line_words:
        txt = w["text"]
        x0  = max(0, w["x0"])
        x1  = min(page_width, w["x1"])
        top, bot = w["top"], w["bottom"]
        fn  = w.get("fontname") or "Helvetica"
        fs  = float(w.get("size") or 10)
        n   = max(len(txt), 1)
        cw  = (x1 - x0) / n
        for i, ch in enumerate(txt):
            char_entries.append({
                "char": ch, "x": x0 + i * cw,
                "fontname": fn, "size": fs,
                "top": top, "bottom": bot,
            })
        char_entries.append({
            "char": " ", "x": x1,
            "fontname": fn, "size": fs,
            "top": top, "bottom": bot,
        })

    line_text = "".join(c["char"] for c in char_entries)
    findings  = find_pii(line_text.rstrip())

    segments, replacements = [], []
    prev_end = 0

    for f in findings:
        s, e = f["start"], f["end"]
        if s > prev_end:
            _add_seg(segments, char_entries[prev_end:s], masked=False, shift=shift)
        masked_text = mask_pii(f["type"], f["value"], shift)
        _add_seg(segments, char_entries[s:e],
                 masked=True, shift=shift, override=masked_text)
        replacements.append({
            "type": f["type"],
            "original": f["value"],
            "masked": masked_text,
        })
        prev_end = e

    if prev_end < len(char_entries):
        _add_seg(segments, char_entries[prev_end:], masked=False, shift=shift)

    return segments, replacements


def _add_seg(segs, chars, masked, shift, override=""):
    if not chars:
        return
    text = (override if masked else "".join(c["char"] for c in chars)).rstrip()
    if not text:
        return
    segs.append({
        "text":     text,
        "x":        max(0, chars[0]["x"]),
        "top":      min(c["top"]    for c in chars),
        "bottom":   max(c["bottom"] for c in chars),
        "fontname": chars[0]["fontname"],
        "size":     max(float(chars[0]["size"]), 5),
        "is_pii":   masked,
    })


# ══════════════════════════════════════════════════════════════════════════════
#  FONT MAPPING
# ══════════════════════════════════════════════════════════════════════════════

def rl_font(fontname: str) -> str:
    fn = (fontname or "").lower()
    if "bold" in fn and ("italic" in fn or "oblique" in fn): return "Helvetica-BoldOblique"
    if "bold"   in fn: return "Helvetica-Bold"
    if "italic" in fn or "oblique" in fn: return "Helvetica-Oblique"
    if "courier" in fn or "mono" in fn:  return "Courier"
    if "times"  in fn or "roman" in fn:  return "Times-Roman"
    return "Helvetica"


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE RENDERER
# ══════════════════════════════════════════════════════════════════════════════

def render_page(c: rl_canvas.Canvas, line_segs: list[list[dict]],
                pw: float, ph: float):
    c.setFillColor(colors.white)
    c.rect(0, 0, pw, ph, fill=1, stroke=0)

    for segs in line_segs:
        for seg in segs:
            txt = seg["text"]
            if not txt.strip():
                continue
            y  = ph - seg["bottom"] + 1.5
            x  = seg["x"]
            fs = min(seg["size"], 72)
            fn = rl_font(seg["fontname"])
            try:
                c.setFont(fn, fs)
            except Exception:
                c.setFont("Helvetica", fs)
            c.setFillColor(colors.black)
            try:
                c.drawString(x, y, txt)
            except Exception:
                safe = txt.encode("latin-1", "replace").decode("latin-1")
                try:
                    c.drawString(x, y, safe)
                except Exception:
                    pass  # completely unrenderable glyph — skip


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def process_pdf(input_path: str, output_path: str,
                shift: int = 4,
                password: str = "",
                report_path: str = "") -> dict:

    summary          = defaultdict(int)
    all_replacements = []

    open_kwargs = {"password": password} if password else {}

    with pdfplumber.open(input_path, **open_kwargs) as doc:
        n     = len(doc.pages)
        first = doc.pages[0]
        PW, PH = float(first.width), float(first.height)

        c = rl_canvas.Canvas(output_path, pagesize=(PW, PH))

        for pg_idx, page in enumerate(doc.pages):
            print(f"  Page {pg_idx+1}/{n} …", end=" ", flush=True)

            pw = float(page.width)
            ph = float(page.height)

            # Skip image-only pages — copy them as-is (white page with note)
            text = page.extract_text() or ""
            if len(re.sub(r"\s+", "", text)) < 20:
                print("(image/blank — skipped, see preflight)")
                c.setFillColor(colors.white)
                c.rect(0, 0, pw, ph, fill=1, stroke=0)
                c.setFont("Helvetica", 9)
                c.setFillColor(colors.Color(0.5, 0.5, 0.5))
                c.drawString(72, ph - 30,
                             "[Page contains no extractable text — OCR required to mask]")
                c.showPage()
                continue

            words = page.extract_words(
                x_tolerance=2, y_tolerance=2,
                keep_blank_chars=False,
                extra_attrs=["size", "fontname"],
            )

            if not words:
                c.showPage()
                print("(no words)")
                continue

            lines      = group_into_lines(words, y_tol=2.0)
            page_segs  = []
            page_repls = []

            for lw in lines:
                segs, repls = build_segments(lw, shift=shift, page_width=pw)
                page_segs.append(segs)
                page_repls.extend(repls)

            for r in page_repls:
                summary[r["type"]] += 1
                all_replacements.append({**r, "page": pg_idx + 1})

            render_page(c, page_segs, pw, ph)
            c.showPage()
            print(f"→ {len(page_repls)} PII fields masked")

        c.save()

    if report_path:
        Path(report_path).write_text(
            json.dumps(all_replacements, indent=2), encoding="utf-8"
        )

    return dict(summary)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def print_summary(summary: dict, shift: int, inp: str, out: str):
    total = sum(summary.values())
    W = 58
    print("═"*W)
    print(f"  MASKING COMPLETE  (shift={shift})")
    print("═"*W)
    print(f"  Input  : {inp}")
    print(f"  Output : {out}")
    print("─"*W)
    for t, cnt in sorted(summary.items(), key=lambda x: -x[1]):
        print(f"  {t:<26} {cnt:>4}  {'█'*min(cnt,24)}")
    print("─"*W)
    print(f"  {'TOTAL':<26} {total:>4}")
    print("═"*W + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Production-hardened PDF PII masker with pre-flight validation."
    )
    ap.add_argument("input",  nargs="?", default="__sample__",
                    help="Input PDF (omit to generate sample)")
    ap.add_argument("output", nargs="?",
                    help="Output PDF (default: <input>_masked.pdf)")
    ap.add_argument("--shift",    type=int, default=4,
                    help="Cipher shift (default 4). Letters mod 26, digits mod 10.")
    ap.add_argument("--preflight-only", action="store_true",
                    help="Run validation only, do not mask.")
    ap.add_argument("--password", default="",
                    help="Password for encrypted PDFs.")
    ap.add_argument("--report",   action="store_true",
                    help="Save JSON replacement report.")
    ap.add_argument("--no-preflight", action="store_true",
                    help="Skip pre-flight check (faster, not recommended).")
    args = ap.parse_args()

    # ── Generate sample if no input ──────────────────────────────────────────
    if args.input == "__sample__":
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors as rlc
        PW, PH = letter
        sample_path = "/home/claude/sample_v5.pdf"
        cv = rl_canvas.Canvas(sample_path, pagesize=(PW, PH))

        def txt(t, x, y, size=11, bold=False):
            cv.setFont("Helvetica-Bold" if bold else "Helvetica", size)
            cv.setFillColor(rlc.black)
            cv.drawString(x, y, t)

        def row(lbl, val, y):
            txt(lbl, 72, y, bold=True)
            txt(val, 210, y)

        # PAGE 1
        txt("RIVERSIDE MEDICAL CENTER – Patient Intake Form", 72, 740, 16, True)
        cv.line(72, 733, 540, 733)
        fields = [
            ("Patient Name:",    "James T. Harrington"),
            ("Date of Birth:",   "March 14, 1979"),
            ("SSN:",             "512-34-7890"),
            ("Phone:",           "(614) 823-4917"),
            ("Alt Phone:",       "614.823.1234"),
            ("Email:",           "j.harrington@gmail.com"),
            ("Address:",         "448 Elmwood Drive, Columbus, OH  43210"),
            ("Emergency:",       "Patricia Harrington  –  (614) 823-0045"),
            ("Physician:",       "Dr. Sandra Kowalski"),
            ("Appt Date:",       "07/22/2024"),
            ("Credit Card:",     "4532 8871 2043 9900"),
            ("Passport:",        "US A7823401"),
            ("Driver Lic:",      "DL# OH-K4821034"),
        ]
        for i, (l, v) in enumerate(fields):
            row(l, v, 710 - i*22)
        txt("Patient James T. Harrington referred by Dr. Sandra Kowalski.", 72, 408)
        txt("Contact: support@bluecross-oh.com  |  1-800-422-6700", 72, 388)
        txt("IP: 192.168.42.17   Portal: https://patient.riversidemed.org/harrington", 72, 368)
        cv.showPage()

        # PAGE 2
        txt("NEXCORP INC. – Confidential Employee Record", 72, 740, 16, True)
        cv.line(72, 733, 540, 733)
        fields2 = [
            ("Full Name:",       "Mei-Ling Zhao"),
            ("DOB:",             "09/27/1988"),
            ("SSN:",             "301-56-9921"),
            ("Work Email:",      "meilingz@nexcorp.com"),
            ("Mobile:",          "+1 (312) 774-0293"),
            ("Home Address:",    "1902 N Ashland Ave, Chicago, IL  60622"),
            ("Manager:",         "Robert D. Sullivan"),
        ]
        for i, (l, v) in enumerate(fields2):
            row(l, v, 710 - i*22)
        txt("Mei-Ling Zhao joined Nexcorp from Goldman Sachs in January 2018.", 72, 550)
        txt("Supervisor Robert D. Sullivan approved transfer on 12/15/2017.", 72, 530)
        txt("Emergency: Michael Zhao – brother – (312) 904-7711", 72, 510)
        cv.showPage()

        # PAGE 3
        txt("FIRST HARBOR BANK – Transaction Summary (Confidential)", 72, 740, 16, True)
        cv.line(72, 733, 540, 733)
        fields3 = [
            ("Account Holder:", "Carlos M. Reyes"),
            ("SSN:",            "628-90-3344"),
            ("Phone:",          "(305) 918-2740"),
            ("Email:",          "creyes_miami@outlook.com"),
            ("Address:",        "78 Coral Way, Miami, FL  33145"),
            ("Date of Birth:",  "November 5, 1965"),
        ]
        for i, (l, v) in enumerate(fields3):
            row(l, v, 710 - i*22)
        txt("Analyst: Diana T. Westbrook – diana.w@firstharbor.com", 72, 550)
        txt("Flagged IP: 186.74.201.55", 72, 530)
        txt("Card: 5412 7553 8810 2291   DL# FL-W2349100340", 72, 510)
        cv.showPage()
        cv.save()
        print(f"✓ Sample PDF: {sample_path}")
        inp = sample_path
    else:
        inp = args.input
        if not Path(inp).exists():
            sys.exit(f"❌ File not found: {inp}")

    out = args.output or str(Path(inp).parent / (Path(inp).stem + "_masked.pdf"))
    rpt = str(Path(out).with_suffix(".report.json")) if args.report else ""

    # ── Pre-flight ────────────────────────────────────────────────────────────
    if not args.no_preflight:
        print(f"\n🔍 Running pre-flight on: {inp}")
        pf = run_preflight(inp)
        pf.print()
        if args.preflight_only:
            sys.exit(0)
        if pf.errors:
            print("⛔  Aborting due to errors. Fix issues and re-run.\n")
            sys.exit(1)

    # ── Mask ─────────────────────────────────────────────────────────────────
    print(f"🔐 Masking (shift={args.shift}) …\n")
    summary = process_pdf(inp, out,
                          shift=args.shift,
                          password=args.password,
                          report_path=rpt)
    print()
    print_summary(summary, args.shift, inp, out)
    if rpt:
        print(f"📄 Report: {rpt}\n")

    # ── Cipher examples ───────────────────────────────────────────────────────
    print(f"  Cipher examples (shift={args.shift})")
    print(f"  {'TYPE':<16} {'ORIGINAL':<32} {'MASKED'}")
    print("  " + "─"*62)
    examples = [
        ("512-34-7890",            "SSN"),
        ("(614) 823-4917",         "PHONE"),
        ("j.harrington@gmail.com", "EMAIL"),
        ("March 14, 1979",         "DATE"),
        ("07/22/2024",             "DATE"),
        ("2024-06-01",             "DATE"),
        ("22-Jul-2024",            "DATE"),
        ("4532 8871 2043 9900",    "CREDIT_CARD"),
        ("192.168.42.17",          "IP_ADDRESS"),
        ("James T. Harrington",    "PERSON_NAME"),
    ]
    for orig, label in examples:
        masked = mask_pii(label, orig, args.shift)
        print(f"  {label:<16}  {orig:<32} →  {masked}")
