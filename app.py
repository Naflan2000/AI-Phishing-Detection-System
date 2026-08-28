import os
import sys
import json
import csv
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import joblib


# ============================================================
# AI-BASED PHISHING DETECTION SYSTEM
# PREMIUM ULTRA v2.0
# ============================================================

APP_NAME = "AI PHISHING DETECTION SYSTEM"
APP_VERSION = "PREMIUM ULTRA v2.0"


# ============================================================
# APPLICATION PATH
# ============================================================

def application_directory():
    if getattr(sys, "frozen", False):
        return os.path.dirname(
            os.path.abspath(sys.executable)
        )

    return os.path.dirname(
        os.path.abspath(__file__)
    )


APP_DIR = application_directory()


def resource_path(filename):
    """
    Works both with normal Python execution
    and PyInstaller.
    """

    if getattr(sys, "frozen", False):

        base = getattr(
            sys,
            "_MEIPASS",
            APP_DIR
        )

    else:

        base = APP_DIR

    return os.path.join(
        base,
        filename
    )


# ============================================================
# MODEL FILE SEARCH
# ============================================================

MODEL_CANDIDATES = [
    "logistic_regression_model.pkl",
    "logistic_regression_model_v2.pkl",
    "random_forest_model.pkl",
    "random_forest_model_v2.pkl",
    "phishing_model.pkl",
    "model.pkl"
]

VECTORIZER_CANDIDATES = [
    "tfidf_vectorizer_final.pkl",
    "tfidf_vectorizer_v2.pkl",
    "tfidf_vectorizer.pkl",
    "vectorizer.pkl"
]


def find_file(candidates):

    for filename in candidates:

        path = resource_path(filename)

        if os.path.exists(path):

            return path

    return None


MODEL_PATH = find_file(
    MODEL_CANDIDATES
)

VECTORIZER_PATH = find_file(
    VECTORIZER_CANDIDATES
)


# ============================================================
# LOAD MACHINE LEARNING MODEL
# ============================================================

model = None
vectorizer = None
model_error = None


try:

    if MODEL_PATH is None:

        raise FileNotFoundError(
            "No trained model file was found."
        )

    if VECTORIZER_PATH is None:

        raise FileNotFoundError(
            "No TF-IDF vectorizer file was found."
        )

    model = joblib.load(
        MODEL_PATH
    )

    vectorizer = joblib.load(
        VECTORIZER_PATH
    )

except Exception as error:

    model_error = str(error)


# ============================================================
# PERSISTENT HISTORY
# ============================================================

HISTORY_FILE = os.path.join(
    APP_DIR,
    "scan_history.json"
)

scan_history = []


def load_history():

    global scan_history

    try:

        if not os.path.exists(
            HISTORY_FILE
        ):

            scan_history = []

            return

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):

            scan_history = data

        else:

            scan_history = []

    except Exception:

        scan_history = []


def save_history():

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                scan_history,
                file,
                indent=4
            )

    except Exception as error:

        print(
            "History save error:",
            error
        )


load_history()


# ============================================================
# COLOURS
# ============================================================

BG = "#07111F"
PANEL = "#0D1B2A"
PANEL2 = "#12263A"
INPUT = "#081522"

WHITE = "#F8FAFC"
MUTED = "#8FA3B8"

CYAN = "#38BDF8"
BLUE = "#2563EB"

GREEN = "#22C55E"
RED = "#EF4444"
YELLOW = "#F59E0B"

BORDER = "#20354A"


# ============================================================
# MAIN WINDOW
# ============================================================

root = tk.Tk()

root.title(
    f"{APP_NAME} | {APP_VERSION}"
)

root.geometry(
    "1250x850"
)

root.minsize(
    1050,
    720
)

root.configure(
    bg=BG
)


# ============================================================
# TK VARIABLES
# ============================================================

animation_job = None


# ============================================================
# STYLE
# ============================================================

style = ttk.Style()

try:

    style.theme_use(
        "clam"
    )

except Exception:

    pass


style.configure(
    "Premium.Horizontal.TProgressbar",
    troughcolor=PANEL2,
    background=CYAN,
    bordercolor=PANEL2,
    lightcolor=CYAN,
    darkcolor=CYAN,
    thickness=8
)


# ============================================================
# SOUND
# ============================================================

def play_sound(sound_type):

    try:

        import winsound

        if sound_type == "success":

            winsound.MessageBeep(
                winsound.MB_ICONASTERISK
            )

        elif sound_type == "warning":

            winsound.MessageBeep(
                winsound.MB_ICONEXCLAMATION
            )

        else:

            winsound.MessageBeep()

    except Exception:

        pass


# ============================================================
# UI HELPERS
# ============================================================

def create_button(
    parent,
    text,
    command,
    background=PANEL2,
    foreground=WHITE
):

    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=background,
        fg=foreground,
        activebackground=background,
        activeforeground=foreground,
        relief="flat",
        bd=0,
        cursor="hand2",
        font=(
            "Segoe UI",
            9,
            "bold"
        ),
        padx=14,
        pady=9
    )


def create_card(parent):

    return tk.Frame(
        parent,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1
    )


# ============================================================
# STATISTICS
# ============================================================

def total_scans():

    return len(
        scan_history
    )


def phishing_count():

    return sum(
        1
        for item in scan_history
        if item.get(
            "prediction"
        ) == "PHISHING"
    )


def legitimate_count():

    return sum(
        1
        for item in scan_history
        if item.get(
            "prediction"
        ) == "LEGITIMATE"
    )


def update_dashboard():

    total_value.config(
        text=str(
            total_scans()
        )
    )

    phishing_value.config(
        text=str(
            phishing_count()
        )
    )

    legitimate_value.config(
        text=str(
            legitimate_count()
        )
    )


# ============================================================
# INPUT VALIDATION
# ============================================================

def validate_email(text):

    text = text.strip()

    if not text:

        return False, (
            "Please enter an email message."
        )

    words = text.split()

    character_count = len(
        text
    )

    alphabetic_count = sum(
        1
        for character in text
        if character.isalpha()
    )

    # Prevent very short inputs such as:
    # hii
    # hello
    # test
    # ok
    if (
        len(words) < 5
        or character_count < 20
        or alphabetic_count < 10
    ):

        return False, (
            "The message contains insufficient "
            "content for reliable classification."
        )

    return True, ""


# ============================================================
# PROGRESS ANIMATION
# ============================================================

def set_progress(value):

    progress["value"] = value


def start_progress_animation():

    global animation_job

    if animation_job is not None:

        try:

            root.after_cancel(
                animation_job
            )

        except Exception:

            pass

    progress["value"] = 0

    animate_progress(
        0
    )


def animate_progress(value):

    global animation_job

    if value >= 90:

        progress["value"] = 90

        animation_job = None

        return

    progress["value"] = value

    animation_job = root.after(
        25,
        lambda: animate_progress(
            value + 4
        )
    )


def stop_progress_animation():

    global animation_job

    if animation_job is not None:

        try:

            root.after_cancel(
                animation_job
            )

        except Exception:

            pass

        animation_job = None

    progress["value"] = 100


# ============================================================
# RESET RESULT
# ============================================================

def reset_result():

    result_label.config(
        text="READY FOR ANALYSIS",
        fg=MUTED
    )

    confidence_value.config(
        text="--"
    )

    risk_value.config(
        text="--",
        fg=MUTED
    )

    status_label.config(
        text="SYSTEM READY",
        fg=GREEN
    )

    recommendation_label.config(
        text=(
            "Enter a complete email message "
            "to begin analysis."
        )
    )

    details_label.config(
        text="No email analysed."
    )

    progress["value"] = 0


# ============================================================
# CLEAR INPUT
# ============================================================

def clear_input():

    email_input.delete(
        "1.0",
        tk.END
    )

    reset_result()


# ============================================================
# SAMPLE EMAILS
# ============================================================

def phishing_sample():

    email_input.delete(
        "1.0",
        tk.END
    )

    email_input.insert(
        "1.0",
        """URGENT SECURITY ALERT

Your bank account has been temporarily suspended
because unusual activity was detected.

Click the verification link immediately to restore
your account. You must confirm your password and
personal information within 24 hours.

Failure to complete this verification may result
in permanent account suspension.

Please verify your account immediately."""
    )

    status_label.config(
        text="PHISHING SAMPLE LOADED",
        fg=YELLOW
    )


def legitimate_sample():

    email_input.delete(
        "1.0",
        tk.END
    )

    email_input.insert(
        "1.0",
        """Dear Team,

Our project meeting is scheduled for tomorrow
at 10:00 AM.

Please review the project documentation before
the meeting. We will discuss the current project
progress, upcoming tasks, and the final implementation
schedule.

Best regards,
Project Team"""
    )

    status_label.config(
        text="LEGITIMATE SAMPLE LOADED",
        fg=CYAN
    )


# ============================================================
# DETECTION
# ============================================================

def detect_email():

    email_text = email_input.get(
        "1.0",
        tk.END
    ).strip()

    valid, error_message = validate_email(
        email_text
    )

    if not valid:

        stop_progress_animation()

        result_label.config(
            text="⚠ INSUFFICIENT CONTENT",
            fg=YELLOW
        )

        confidence_value.config(
            text="--"
        )

        risk_value.config(
            text="NOT CLASSIFIED",
            fg=YELLOW
        )

        status_label.config(
            text="INPUT REQUIRES MORE CONTENT",
            fg=YELLOW
        )

        recommendation_label.config(
            text=(
                error_message
                + " Please provide a complete "
                "email message."
            )
        )

        details_label.config(
            text="Message was not submitted to the classifier."
        )

        progress["value"] = 0

        return

    if model is None or vectorizer is None:

        messagebox.showerror(
            "Model Error",
            "The trained model could not be loaded.\n\n"
            f"Model: {MODEL_PATH}\n"
            f"Vectorizer: {VECTORIZER_PATH}\n\n"
            f"Error:\n{model_error}"
        )

        return

    scan_button.config(
        state="disabled"
    )

    status_label.config(
        text="ANALYSING EMAIL...",
        fg=CYAN
    )

    start_progress_animation()

    root.after(
        500,
        lambda: perform_detection(
            email_text
        )
    )


def perform_detection(email_text):

    try:

        features = vectorizer.transform(
            [email_text]
        )

        prediction = int(
            model.predict(
                features
            )[0]
        )

        # ====================================================
        # CONFIDENCE
        # ====================================================

        if hasattr(
            model,
            "predict_proba"
        ):

            probabilities = (
                model.predict_proba(
                    features
                )[0]
            )

            confidence = (
                max(probabilities)
                * 100
            )

        else:

            confidence = 0.0

        # ====================================================
        # CLASSIFICATION
        # ====================================================

        if prediction == 1:

            prediction_name = (
                "PHISHING"
            )

            result_text = (
                "⚠ PHISHING EMAIL"
            )

            result_color = RED

            if confidence >= 80:

                risk = "HIGH"

            elif confidence >= 60:

                risk = "MEDIUM"

            else:

                risk = "LOW"

            recommendation = (
                "HIGH CAUTION: Do not click suspicious "
                "links, open unknown attachments, or "
                "provide passwords, banking information, "
                "OTP codes, or other sensitive information."
            )

            play_sound(
                "warning"
            )

        else:

            prediction_name = (
                "LEGITIMATE"
            )

            result_text = (
                "✓ LEGITIMATE EMAIL"
            )

            result_color = GREEN

            if confidence >= 80:

                risk = "LOW"

            elif confidence >= 60:

                risk = "MEDIUM"

            else:

                risk = "LOW"

            recommendation = (
                "The trained model did not classify this "
                "message as phishing. Continue following "
                "normal email security practices."
            )

            play_sound(
                "success"
            )

        # ====================================================
        # MESSAGE INFORMATION
        # ====================================================

        characters = len(
            email_text
        )

        words = len(
            email_text.split()
        )

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # ====================================================
        # SAVE HISTORY
        # ====================================================

        record = {
            "timestamp": timestamp,
            "prediction": prediction_name,
            "risk": risk,
            "confidence": round(
                confidence,
                2
            ),
            "characters": characters,
            "words": words
        }

        scan_history.append(
            record
        )

        # Keep last 500 records

        if len(scan_history) > 500:

            del scan_history[
                :-500
            ]

        save_history()

        # ====================================================
        # UPDATE UI
        # ====================================================

        stop_progress_animation()

        scan_button.config(
            state="normal"
        )

        result_label.config(
            text=result_text,
            fg=result_color
        )

        confidence_value.config(
            text=f"{confidence:.2f}%"
        )

        risk_value.config(
            text=risk,
            fg=result_color
        )

        status_label.config(
            text="ANALYSIS COMPLETE",
            fg=result_color
        )

        recommendation_label.config(
            text=recommendation
        )

        details_label.config(
            text=(
                f"Characters: {characters:,}   •   "
                f"Words: {words:,}   •   "
                "Model: Logistic Regression / "
                "Selected trained classifier   •   "
                "Features: TF-IDF"
            )
        )

        update_dashboard()

    except Exception as error:

        stop_progress_animation()

        scan_button.config(
            state="normal"
        )

        messagebox.showerror(
            "Prediction Error",
            str(error)
        )

        status_label.config(
            text="ANALYSIS ERROR",
            fg=RED
        )


# ============================================================
# HISTORY WINDOW
# ============================================================

def show_history():

    window = tk.Toplevel(
        root
    )

    window.title(
        "AI Phishing Detector - Scan History"
    )

    window.geometry(
        "980x650"
    )

    window.configure(
        bg=BG
    )

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    tk.Label(
        window,
        text="SCAN HISTORY",
        font=(
            "Segoe UI",
            20,
            "bold"
        ),
        bg=BG,
        fg=WHITE
    ).pack(
        pady=(25, 3)
    )

    tk.Label(
        window,
        text=(
            f"{len(scan_history)} stored analyses"
        ),
        font=(
            "Segoe UI",
            9
        ),
        bg=BG,
        fg=MUTED
    ).pack(
        pady=(0, 15)
    )

    # --------------------------------------------------------
    # SEARCH
    # --------------------------------------------------------

    search_frame = tk.Frame(
        window,
        bg=BG
    )

    search_frame.pack(
        fill="x",
        padx=30,
        pady=(0, 12)
    )

    search_var = tk.StringVar()

    search_entry = tk.Entry(
        search_frame,
        textvariable=search_var,
        font=(
            "Segoe UI",
            10
        ),
        bg=INPUT,
        fg=WHITE,
        insertbackground=WHITE,
        relief="flat"
    )

    search_entry.pack(
        side="left",
        fill="x",
        expand=True,
        ipady=9
    )

    # --------------------------------------------------------
    # HISTORY TABLE
    # --------------------------------------------------------

    table_frame = tk.Frame(
        window,
        bg=PANEL
    )

    table_frame.pack(
        fill="both",
        expand=True,
        padx=30,
        pady=(0, 15)
    )

    columns = (
        "No",
        "Timestamp",
        "Result",
        "Risk",
        "Confidence",
        "Words"
    )

    tree = ttk.Treeview(
        table_frame,
        columns=columns,
        show="headings"
    )

    headings = {
        "No": "NO.",
        "Timestamp": "TIMESTAMP",
        "Result": "RESULT",
        "Risk": "RISK",
        "Confidence": "CONFIDENCE",
        "Words": "WORDS"
    }

    widths = {
        "No": 55,
        "Timestamp": 180,
        "Result": 150,
        "Risk": 100,
        "Confidence": 110,
        "Words": 80
    }

    for column in columns:

        tree.heading(
            column,
            text=headings[column]
        )

        tree.column(
            column,
            width=widths[column],
            anchor="center"
        )

    scrollbar = ttk.Scrollbar(
        table_frame,
        orient="vertical",
        command=tree.yview
    )

    tree.configure(
        yscrollcommand=scrollbar.set
    )

    tree.pack(
        side="left",
        fill="both",
        expand=True
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    # --------------------------------------------------------
    # TABLE STYLE
    # --------------------------------------------------------

    style.configure(
        "Treeview",
        background=PANEL,
        foreground=WHITE,
        fieldbackground=PANEL,
        rowheight=32,
        borderwidth=0,
        font=(
            "Segoe UI",
            9
        )
    )

    style.configure(
        "Treeview.Heading",
        background=PANEL2,
        foreground=WHITE,
        font=(
            "Segoe UI",
            9,
            "bold"
        )
    )

    # --------------------------------------------------------
    # REFRESH
    # --------------------------------------------------------

    def refresh_table(*args):

        for item in tree.get_children():

            tree.delete(
                item
            )

        query = (
            search_var.get()
            .strip()
            .lower()
        )

        filtered = []

        for item in reversed(
            scan_history
        ):

            searchable = str(
                item
            ).lower()

            if query in searchable:

                filtered.append(
                    item
                )

        for index, item in enumerate(
            filtered,
            start=1
        ):

            tree.insert(
                "",
                "end",
                values=(
                    index,
                    item.get(
                        "timestamp",
                        "-"
                    ),
                    item.get(
                        "prediction",
                        "-"
                    ),
                    item.get(
                        "risk",
                        "-"
                    ),
                    f'{item.get("confidence", 0):.2f}%',
                    item.get(
                        "words",
                        "-"
                    )
                )
            )

    search_var.trace_add(
        "write",
        refresh_table
    )

    refresh_table()

    # --------------------------------------------------------
    # BOTTOM BUTTONS
    # --------------------------------------------------------

    bottom = tk.Frame(
        window,
        bg=BG
    )

    bottom.pack(
        fill="x",
        padx=30,
        pady=(0, 20)
    )

    create_button(
        bottom,
        "EXPORT CSV",
        export_history,
        CYAN,
        "#052337"
    ).pack(
        side="left"
    )

    create_button(
        bottom,
        "CLEAR HISTORY",
        lambda: clear_history(
            window,
            refresh_table
        ),
        RED,
        WHITE
    ).pack(
        side="right"
    )


# ============================================================
# CLEAR HISTORY
# ============================================================

def clear_history(
    window=None,
    refresh_function=None
):

    if not scan_history:

        messagebox.showinfo(
            "History",
            "There is no scan history to clear."
        )

        return

    answer = messagebox.askyesno(
        "Clear History",
        "Delete all saved scan history?"
    )

    if not answer:

        return

    scan_history.clear()

    save_history()

    update_dashboard()

    if refresh_function:

        refresh_function()

    if window:

        window.destroy()

    messagebox.showinfo(
        "History",
        "All scan history has been cleared."
    )


# ============================================================
# EXPORT HISTORY
# ============================================================

def export_history():

    if not scan_history:

        messagebox.showinfo(
            "Export",
            "There is no scan history to export."
        )

        return

    file_path = filedialog.asksaveasfilename(
        title="Export Scan History",
        defaultextension=".csv",
        filetypes=[
            (
                "CSV Files",
                "*.csv"
            )
        ]
    )

    if not file_path:

        return

    try:

        with open(
            file_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "timestamp",
                    "prediction",
                    "risk",
                    "confidence",
                    "characters",
                    "words"
                ]
            )

            writer.writeheader()

            writer.writerows(
                scan_history
            )

        messagebox.showinfo(
            "Export Complete",
            "Scan history exported successfully."
        )

    except Exception as error:

        messagebox.showerror(
            "Export Error",
            str(error)
        )


# ============================================================
# ANALYSIS DETAILS
# ============================================================

def show_details():

    if not scan_history:

        messagebox.showinfo(
            "Analysis Details",
            "Please analyse an email first."
        )

        return

    latest = scan_history[-1]

    window = tk.Toplevel(
        root
    )

    window.title(
        "Security Analysis Details"
    )

    window.geometry(
        "680x600"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="SECURITY ANALYSIS",
        font=(
            "Segoe UI",
            21,
            "bold"
        ),
        bg=BG,
        fg=WHITE
    ).pack(
        pady=(25, 5)
    )

    tk.Label(
        window,
        text="Latest classification result",
        font=(
            "Segoe UI",
            9
        ),
        bg=BG,
        fg=MUTED
    ).pack(
        pady=(0, 20)
    )

    panel = create_card(
        window
    )

    panel.pack(
        fill="both",
        expand=True,
        padx=35,
        pady=(0, 30)
    )

    details = [
        (
            "Timestamp",
            latest.get(
                "timestamp",
                "-"
            )
        ),
        (
            "Prediction",
            latest.get(
                "prediction",
                "-"
            )
        ),
        (
            "Risk Level",
            latest.get(
                "risk",
                "-"
            )
        ),
        (
            "Confidence",
            f'{latest.get("confidence", 0):.2f}%'
        ),
        (
            "Characters",
            f'{latest.get("characters", 0):,}'
        ),
        (
            "Words",
            f'{latest.get("words", 0):,}'
        ),
        (
            "Feature Extraction",
            "TF-IDF"
        ),
        (
            "Classification",
            "Binary Classification"
        ),
        (
            "Application Version",
            APP_VERSION
        )
    ]

    for label_text, value in details:

        row = tk.Frame(
            panel,
            bg=PANEL
        )

        row.pack(
            fill="x",
            padx=25,
            pady=8
        )

        tk.Label(
            row,
            text=label_text,
            width=27,
            anchor="w",
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            bg=PANEL,
            fg=MUTED
        ).pack(
            side="left"
        )

        value_color = WHITE

        if value == "PHISHING":

            value_color = RED

        elif value == "LEGITIMATE":

            value_color = GREEN

        elif value == "HIGH":

            value_color = RED

        elif value == "MEDIUM":

            value_color = YELLOW

        elif value == "LOW":

            value_color = GREEN

        tk.Label(
            row,
            text=value,
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            bg=PANEL,
            fg=value_color
        ).pack(
            side="left"
        )


# ============================================================
# ABOUT
# ============================================================

def show_about():

    messagebox.showinfo(
        "About AI Phishing Detection System",
        "AI-BASED PHISHING DETECTION SYSTEM\n\n"
        "Premium Ultra Edition v2.0\n\n"
        "Machine Learning:\n"
        "Logistic Regression / Trained Classifier\n\n"
        "Feature Extraction:\n"
        "TF-IDF\n\n"
        "Validation Results:\n"
        "Accuracy: 98.89%\n"
        "Precision: 98.85%\n"
        "Recall: 99.02%\n"
        "F1 Score: 98.93%\n\n"
        "Features:\n"
        "• AI email classification\n"
        "• Confidence estimation\n"
        "• Risk assessment\n"
        "• Persistent scan history\n"
        "• Searchable history\n"
        "• CSV export\n"
        "• Security recommendations\n"
        "• Premium dashboard\n"
        "• Sound feedback\n"
        "• PyInstaller compatible"
    )


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    root,
    bg=BG
)

header.pack(
    fill="x",
    padx=35,
    pady=(25, 15)
)


tk.Label(
    header,
    text="🛡",
    font=(
        "Segoe UI Emoji",
        34
    ),
    bg=BG,
    fg=CYAN
).pack(
    side="left",
    padx=(0, 15)
)


title_frame = tk.Frame(
    header,
    bg=BG
)

title_frame.pack(
    side="left"
)


tk.Label(
    title_frame,
    text=APP_NAME,
    font=(
        "Segoe UI",
        25,
        "bold"
    ),
    bg=BG,
    fg=WHITE
).pack(
    anchor="w"
)


tk.Label(
    title_frame,
    text=(
        "INTELLIGENT EMAIL SECURITY "
        "AND PHISHING ANALYSIS PLATFORM"
    ),
    font=(
        "Segoe UI",
        9,
        "bold"
    ),
    bg=BG,
    fg=MUTED
).pack(
    anchor="w"
)


create_button(
    header,
    "ABOUT",
    show_about
).pack(
    side="right"
)


create_button(
    header,
    "HISTORY",
    show_history
).pack(
    side="right",
    padx=8
)


# ============================================================
# STATISTICS
# ============================================================

stats_frame = tk.Frame(
    root,
    bg=BG
)

stats_frame.pack(
    fill="x",
    padx=35,
    pady=(0, 15)
)


def create_stat_card(
    parent,
    title,
    value,
    icon
):

    frame = tk.Frame(
        parent,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    frame.pack(
        side="left",
        fill="x",
        expand=True,
        padx=5
    )

    tk.Label(
        frame,
        text=icon,
        font=(
            "Segoe UI Emoji",
            19
        ),
        bg=PANEL,
        fg=CYAN
    ).pack(
        side="left",
        padx=(15, 10),
        pady=12
    )

    text_frame = tk.Frame(
        frame,
        bg=PANEL
    )

    text_frame.pack(
        side="left"
    )

    tk.Label(
        text_frame,
        text=title,
        font=(
            "Segoe UI",
            8,
            "bold"
        ),
        bg=PANEL,
        fg=MUTED
    ).pack(
        anchor="w"
    )

    value_label = tk.Label(
        text_frame,
        text=value,
        font=(
            "Segoe UI",
            16,
            "bold"
        ),
        bg=PANEL,
        fg=WHITE
    )

    value_label.pack(
        anchor="w"
    )

    return value_label


total_value = create_stat_card(
    stats_frame,
    "TOTAL SCANS",
    str(
        total_scans()
    ),
    "◉"
)


phishing_value = create_stat_card(
    stats_frame,
    "PHISHING DETECTED",
    str(
        phishing_count()
    ),
    "⚠"
)


legitimate_value = create_stat_card(
    stats_frame,
    "LEGITIMATE",
    str(
        legitimate_count()
    ),
    "✓"
)


# ============================================================
# MAIN AREA
# ============================================================

main_frame = tk.Frame(
    root,
    bg=BG
)

main_frame.pack(
    fill="both",
    expand=True,
    padx=35
)


# ============================================================
# EMAIL ANALYSIS CARD
# ============================================================

email_card = create_card(
    main_frame
)

email_card.pack(
    fill="both",
    expand=True
)


tk.Label(
    email_card,
    text="EMAIL ANALYSIS",
    font=(
        "Segoe UI",
        13,
        "bold"
    ),
    bg=PANEL,
    fg=WHITE
).pack(
    anchor="w",
    padx=25,
    pady=(20, 3)
)


tk.Label(
    email_card,
    text=(
        "Paste a complete email message below. "
        "The system will analyse the content using "
        "machine learning and TF-IDF text features."
    ),
    font=(
        "Segoe UI",
        9
    ),
    bg=PANEL,
    fg=MUTED,
    wraplength=1000,
    justify="left"
).pack(
    anchor="w",
    padx=25,
    pady=(0, 12)
)


email_input = tk.Text(
    email_card,
    height=10,
    bg=INPUT,
    fg=WHITE,
    insertbackground=WHITE,
    selectbackground="#24415A",
    font=(
        "Segoe UI",
        10
    ),
    relief="flat",
    wrap="word",
    padx=15,
    pady=15
)

email_input.pack(
    fill="both",
    expand=True,
    padx=25
)


# ============================================================
# PROGRESS BAR
# ============================================================

progress_frame = tk.Frame(
    email_card,
    bg=PANEL
)

progress_frame.pack(
    fill="x",
    padx=25,
    pady=(10, 4)
)


progress = ttk.Progressbar(
    progress_frame,
    style="Premium.Horizontal.TProgressbar",
    orient="horizontal",
    mode="determinate",
    maximum=100
)

progress.pack(
    fill="x"
)

progress["value"] = 0


# ============================================================
# BUTTON BAR
# ============================================================

controls = tk.Frame(
    email_card,
    bg=PANEL
)

controls.pack(
    fill="x",
    padx=25,
    pady=10
)


scan_button = create_button(
    controls,
    "🔍  ANALYZE EMAIL",
    detect_email,
    CYAN,
    "#052337"
)

scan_button.pack(
    side="left"
)


create_button(
    controls,
    "CLEAR",
    clear_input
).pack(
    side="left",
    padx=6
)


create_button(
    controls,
    "PHISHING SAMPLE",
    phishing_sample
).pack(
    side="left",
    padx=6
)


create_button(
    controls,
    "LEGITIMATE SAMPLE",
    legitimate_sample
).pack(
    side="left",
    padx=6
)


create_button(
    controls,
    "DETAILS",
    show_details
).pack(
    side="right"
)


# ============================================================
# RESULT CARD
# ============================================================

result_card = create_card(
    main_frame
)

result_card.pack(
    fill="x",
    pady=(15, 0)
)


status_label = tk.Label(
    result_card,
    text="SYSTEM READY",
    font=(
        "Segoe UI",
        8,
        "bold"
    ),
    bg=PANEL,
    fg=GREEN
)

status_label.pack(
    pady=(12, 2)
)


result_label = tk.Label(
    result_card,
    text="READY FOR ANALYSIS",
    font=(
        "Segoe UI",
        20,
        "bold"
    ),
    bg=PANEL,
    fg=MUTED
)

result_label.pack(
    pady=3
)


metrics = tk.Frame(
    result_card,
    bg=PANEL
)

metrics.pack(
    pady=7
)


# ============================================================
# CONFIDENCE
# ============================================================

confidence_box = tk.Frame(
    metrics,
    bg=PANEL2,
    padx=35,
    pady=8
)

confidence_box.pack(
    side="left",
    padx=7
)


tk.Label(
    confidence_box,
    text="CONFIDENCE",
    font=(
        "Segoe UI",
        8,
        "bold"
    ),
    bg=PANEL2,
    fg=MUTED
).pack()


confidence_value = tk.Label(
    confidence_box,
    text="--",
    font=(
        "Segoe UI",
        16,
        "bold"
    ),
    bg=PANEL2,
    fg=CYAN
)

confidence_value.pack()


# ============================================================
# RISK
# ============================================================

risk_box = tk.Frame(
    metrics,
    bg=PANEL2,
    padx=45,
    pady=8
)

risk_box.pack(
    side="left",
    padx=7
)


tk.Label(
    risk_box,
    text="RISK LEVEL",
    font=(
        "Segoe UI",
        8,
        "bold"
    ),
    bg=PANEL2,
    fg=MUTED
).pack()


risk_value = tk.Label(
    risk_box,
    text="--",
    font=(
        "Segoe UI",
        16,
        "bold"
    ),
    bg=PANEL2,
    fg=MUTED
)

risk_value.pack()


# ============================================================
# RECOMMENDATION
# ============================================================

recommendation_label = tk.Label(
    result_card,
    text=(
        "Enter a complete email message "
        "to begin analysis."
    ),
    font=(
        "Segoe UI",
        9
    ),
    bg=PANEL,
    fg=MUTED,
    wraplength=1000,
    justify="center"
)

recommendation_label.pack(
    padx=25,
    pady=(3, 8)
)


# ============================================================
# DETAILS
# ============================================================

details_label = tk.Label(
    result_card,
    text="No email analysed.",
    font=(
        "Segoe UI",
        8
    ),
    bg=PANEL,
    fg=MUTED
)

details_label.pack(
    pady=(0, 12)
)


# ============================================================
# FOOTER
# ============================================================

footer = tk.Frame(
    root,
    bg=BG
)

footer.pack(
    fill="x",
    padx=35,
    pady=12
)


if model is not None and vectorizer is not None:

    model_status = "● MODEL ONLINE"
    model_color = GREEN

else:

    model_status = "● MODEL ERROR"
    model_color = RED


tk.Label(
    footer,
    text=model_status,
    font=(
        "Segoe UI",
        8,
        "bold"
    ),
    bg=BG,
    fg=model_color
).pack(
    side="left"
)


tk.Label(
    footer,
    text=(
        f"TF-IDF  •  Machine Learning  •  "
        f"98.89% Validation Accuracy  •  "
        f"{APP_VERSION}"
    ),
    font=(
        "Segoe UI",
        8
    ),
    bg=BG,
    fg=MUTED
).pack(
    side="right"
)


# ============================================================
# KEYBOARD SHORTCUTS
# ============================================================

root.bind(
    "<Control-Return>",
    lambda event: detect_email()
)

root.bind(
    "<Escape>",
    lambda event: clear_input()
)


# ============================================================
# INITIAL UPDATE
# ============================================================

update_dashboard()


# ============================================================
# START APPLICATION
# ============================================================

root.mainloop()