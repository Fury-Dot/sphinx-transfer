# ═══════════════════════════════════════════════
#  constants.py  —  Colors & Fonts
# ═══════════════════════════════════════════════
from enum import Enum

class Theme(str, Enum):
    # Premium Light Greyscale Colors
    DARK_BG  = "#fcfcfc"   # Main app background (almost white)
    PANEL_BG = "#f2f2f2"   # Sidebar / inner panels (light grey)
    ACCENT   = "#1a1a1a"   # Primary action (charcoal/almost black)
    ACCENT2  = "#333333"   # Secondary accent (dark grey)
    ACCENT3  = "#4d4d4d"   # Tertiary accent (medium dark grey)
    SUCCESS  = "#2b2b2b"   # Success mapped to charcoal for theme purity
    DANGER   = "#000000"   # Danger mapped to pure black for high contrast
    WARNING  = "#555555"   # Warning mapped to medium grey
    TXT      = "#111111"   # High contrast text
    DIM      = "#666666"   # Dim text
    BORDER   = "#e0e0e0"   # Light borders
    
    # Newly extracted values replacing hardcoded hexes
    BOX_BG   = "#e8e8e8"   # Info boxes and column headers
    ROW_BG   = "#fafafa"   # Table row alternating color
    HOVER_BG = "#cccccc"   # Secondary button hover state
    SIDE_SEL = "#e5e5e5"   # Sidebar selected item background

# Keep backward compatibility for smooth transition to CustomTkinter later
DARK_BG  = Theme.DARK_BG
PANEL_BG = Theme.PANEL_BG
ACCENT   = Theme.ACCENT
ACCENT2  = Theme.ACCENT2
ACCENT3  = Theme.ACCENT3
SUCCESS  = Theme.SUCCESS
DANGER   = Theme.DANGER
WARNING  = Theme.WARNING
TXT      = Theme.TXT
DIM      = Theme.DIM
BORDER   = Theme.BORDER
BOX_BG   = Theme.BOX_BG
ROW_BG   = Theme.ROW_BG
HOVER_BG = Theme.HOVER_BG
SIDE_SEL = Theme.SIDE_SEL

# Fonts
FM = ("Courier New", 11)          # mono body
FH = ("Courier New", 22, "bold")  # heading
FS = ("Courier New", 10)          # small
FB = ("Courier New", 11, "bold")  # bold body

# Network
DEFAULT_PORT = 9876