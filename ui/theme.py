"""
ui/theme.py — ARGUS TUI color palette and style constants.

ALL color values are defined here. Nothing is hardcoded in other UI files.
Import this module as: import ui.theme as T
"""

# ---------------------------------------------------------------------------
# Background colors
# ---------------------------------------------------------------------------
BG_MAIN        = "#0d0d1a"   # main terminal background
BG_BANNER      = "#0a0015"   # banner section background
BG_SIDEBAR     = "#08000f"   # sidebar background
BG_STATUSBAR   = "#06000d"   # status bar background

# ---------------------------------------------------------------------------
# Border colors
# ---------------------------------------------------------------------------
BORDER_OUTER   = "#4a00a0"   # outer panel borders
BORDER_INNER   = "#2a004a"   # inner dividers / separator lines

# ---------------------------------------------------------------------------
# Primary palette
# ---------------------------------------------------------------------------
PRIMARY_PURPLE = "#9933ff"   # ASCII art, primary accents
CYAN           = "#00d4ff"   # discoveries, headers, running state
BRIGHT_PURPLE  = "#cc44ff"   # commands, status values
SUCCESS_GREEN  = "#00ff88"   # done state, ok log lines
WARN_YELLOW    = "#ffcc00"   # warnings, hints panel title
DIM_PURPLE     = "#3a2060"   # pending modules, timestamps
MUTED          = "#8888aa"   # info / background log lines
TEXT           = "#e0e0ff"   # default foreground text

# ---------------------------------------------------------------------------
# Accent / special purpose colors
# ---------------------------------------------------------------------------
ACCENT_RED     = "#ff5f57"   # titlebar traffic-light dot (close)
ACCENT_YELLOW  = "#febc2e"   # titlebar traffic-light dot (minimize)
ACCENT_GREEN   = "#28c840"   # titlebar traffic-light dot (maximize)
TITLE_COLOR    = "#7744cc"   # titlebar and section header text
HINT_LABEL     = "#6622aa"   # hint label in the hints panel
BANNER_RIGHT   = "#5533aa"   # banner right subtitle (author line)

# ---------------------------------------------------------------------------
# Composite Rich style strings (safe for use inside Text.append() style arg)
# ---------------------------------------------------------------------------
STYLE_HEADER     = f"bold {CYAN}"
STYLE_RUNNING    = f"bold {CYAN}"
STYLE_DONE       = f"bold {SUCCESS_GREEN}"
STYLE_PENDING    = DIM_PURPLE
STYLE_CMD        = BRIGHT_PURPLE
STYLE_WARN       = WARN_YELLOW
STYLE_SUCCESS    = SUCCESS_GREEN
STYLE_INFO       = MUTED
STYLE_DISCOVERY  = CYAN
STYLE_TITLE      = TITLE_COLOR
STYLE_HINT_TITLE = f"bold {WARN_YELLOW}"
STYLE_HINT_LABEL = HINT_LABEL
STYLE_HINT_CMD   = CYAN
STYLE_TIMESTAMP  = DIM_PURPLE
STYLE_BORDER     = BORDER_OUTER

# ---------------------------------------------------------------------------
# Module status icons
# ---------------------------------------------------------------------------
ICON_DONE    = "[✓]"
ICON_RUNNING = "[>]"
ICON_PENDING = "[ ]"

# ---------------------------------------------------------------------------
# Log prefix → Rich style mapping (ordered: longer prefixes first)
# ---------------------------------------------------------------------------
LOG_STYLES = {
    "[✓]":      STYLE_SUCCESS,    # confirmed success
    "[+]":      STYLE_DISCOVERY,  # discovery / finding
    "[!]":      STYLE_WARN,       # warning / high value
    "[>]":      STYLE_CMD,        # command / running hint
    "[-]":      STYLE_INFO,       # informational
    "[CMD]":    STYLE_CMD,        # engine command echo
    "[DRY-RUN]":STYLE_WARN,       # dry-run mode
    "[WARNING]":STYLE_WARN,       # logger WARNING level
    "[ERROR]":  "bold red",       # logger ERROR level
}

# ---------------------------------------------------------------------------
# Sidebar module list — (display_label, internal_module_key)
# Order matches spec exactly; keys match engine MODULE_REGISTRY names.
# ---------------------------------------------------------------------------
MODULE_LIST = [
    ("RECON", "recon"),       # wrappers/recon.sh (run by engine directly)
    ("SMB",   "smb"),         # modules/smb.py  → wrappers/smb_enum.sh
    ("LDAP",  "ldap"),        # modules/ldap.py → wrappers/ldap_enum.sh
    ("WEB",   "web"),         # modules/web.py  → wrappers/web_enum.sh
    ("DB",    "databases"),   # modules/databases.py → wrappers/db_enum.sh
    ("FTP",   "ftp"),         # modules/ftp.py  → wrappers/ftp_enum.sh
    ("MAIL",  "mail"),        # modules/mail.py → wrappers/mail_enum.sh
    ("NFS",   "nfs"),         # modules/nfs.py  → wrappers/nfs_enum.sh
    ("NET",   "network"),     # modules/network.py → wrappers/network_enum.sh
    ("SVC",   "services"),    # modules/services.py → wrappers/services_enum.sh
    ("RMT",   "remote"),      # modules/remote.py → wrappers/remote_enum.sh
]

# ---------------------------------------------------------------------------
# ARGUS ASCII block-letter art (exact spec reproduction)
# ---------------------------------------------------------------------------
ARGUS_ASCII = (
    " ██████╗ ██████╗  ██████╗ ██╗   ██╗███████╗\n"
    "██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝\n"
    "███████║██████╔╝██║  ███╗██║   ██║███████╗\n"
    "██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║\n"
    "██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║\n"
    "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝"
)
