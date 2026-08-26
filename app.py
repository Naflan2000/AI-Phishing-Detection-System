import tkinter as tk
from tkinter import messagebox
import joblib
import os


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

try:
    model = joblib.load("random_forest_model.pkl")
    vectorizer = joblib.load("tfidf_vectorizer.pkl")
except Exception as e:
    messagebox.showerror(
        "Model Loading Error",
        f"Unable to load the trained model files.\n\n{e}"
    )
    raise


# ============================================================
# COLORS
# ============================================================

BG = "#f4f6f8"
DARK = "#17202a"
WHITE = "#ffffff"
TEXT = "#273746"
GREEN = "#188038"
RED = "#d93025"
GRAY = "#5f6368"
LIGHT = "#e8eaed"


# ============================================================
# ANALYZE EMAIL
# ============================================================

def analyze_email():

    email_text = email_box.get("1.0", tk.END).strip()

    if not email_text:
        messagebox.showwarning(
            "No Email",
            "Please enter or paste an email message."
        )
        return

    try:

        # TF-IDF feature extraction
        email_vector = vectorizer.transform([email_text])

        # Machine learning prediction
        prediction = model.predict(email_vector)[0]

        # Model probability
        probability = model.predict_proba(email_vector)[0]

        confidence = max(probability) * 100

        if prediction == 1:

            result_label.config(
                text="⚠ PHISHING EMAIL DETECTED",
                fg=RED
            )

            risk_label.config(
                text=f"RISK LEVEL: HIGH\nModel Confidence: {confidence:.2f}%",
                fg=RED
            )

        else:

            result_label.config(
                text="✓ LEGITIMATE EMAIL",
                fg=GREEN
            )

            risk_label.config(
                text=f"RISK LEVEL: LOW\nModel Confidence: {confidence:.2f}%",
                fg=GREEN
            )

        model_label.config(
            text="Analysis completed using Random Forest + TF-IDF"
        )

    except Exception as e:

        messagebox.showerror(
            "Analysis Error",
            f"An error occurred during analysis.\n\n{e}"
        )


# ============================================================
# CLEAR
# ============================================================

def clear_email():

    email_box.delete("1.0", tk.END)

    result_label.config(
        text="Waiting for analysis...",
        fg=TEXT
    )

    risk_label.config(
        text="Enter an email and click ANALYZE EMAIL.",
        fg=GRAY
    )

    model_label.config(
        text="Analysis completed using Random Forest + TF-IDF"
    )


# ============================================================
# PHISHING EXAMPLE
# ============================================================

def phishing_example():

    clear_email()

    email_box.insert(
        "1.0",
        "URGENT! Your bank account has been suspended. "
        "Click here immediately to verify your account "
        "and enter your password."
    )


# ============================================================
# LEGITIMATE EXAMPLE
# ============================================================

def legitimate_example():

    clear_email()

    email_box.insert(
        "1.0",
        "Dear team, our project meeting is scheduled for "
        "tomorrow at 10 AM. Please review the attached "
        "project document before the meeting."
    )


# ============================================================
# PERFORMANCE WINDOW
# ============================================================

def show_performance():

    performance = tk.Toplevel(window)

    performance.title("Model Performance")

    performance.geometry("650x560")

    performance.configure(bg=BG)

    performance.resizable(False, False)

    # Header
    header = tk.Frame(
        performance,
        bg=DARK,
        height=90
    )

    header.pack(
        fill="x"
    )

    title = tk.Label(
        header,
        text="MODEL PERFORMANCE",
        font=("Arial", 22, "bold"),
        fg=WHITE,
        bg=DARK
    )

    title.pack(pady=(20, 3))

    subtitle = tk.Label(
        header,
        text="Comparative Machine Learning Evaluation",
        font=("Arial", 11),
        fg="#d5d8dc",
        bg=DARK
    )

    subtitle.pack()

    # Content
    content = tk.Frame(
        performance,
        bg=BG
    )

    content.pack(
        fill="both",
        expand=True,
        padx=35,
        pady=25
    )

    # Model results
    results = [
        ("Naive Bayes", "95.50%"),
        ("Logistic Regression", "98.00%"),
        ("Random Forest", "98.61%")
    ]

    for name, accuracy in results:

        frame = tk.Frame(
            content,
            bg=WHITE,
            relief="solid",
            bd=1
        )

        frame.pack(
            fill="x",
            pady=6
        )

        model_name = tk.Label(
            frame,
            text=name,
            font=("Arial", 13, "bold"),
            bg=WHITE,
            fg=TEXT,
            width=25,
            anchor="w"
        )

        model_name.pack(
            side="left",
            padx=15,
            pady=12
        )

        acc = tk.Label(
            frame,
            text=accuracy,
            font=("Arial", 14, "bold"),
            bg=WHITE,
            fg=TEXT
        )

        acc.pack(
            side="right",
            padx=15
        )

    # Best model
    best_frame = tk.Frame(
        content,
        bg=WHITE,
        relief="solid",
        bd=2
    )

    best_frame.pack(
        fill="x",
        pady=(25, 10)
    )

    best_title = tk.Label(
        best_frame,
        text="BEST PERFORMING MODEL",
        font=("Arial", 12, "bold"),
        bg=WHITE,
        fg=GRAY
    )

    best_title.pack(
        pady=(15, 5)
    )

    best_model = tk.Label(
        best_frame,
        text="RANDOM FOREST",
        font=("Arial", 20, "bold"),
        bg=WHITE,
        fg=GREEN
    )

    best_model.pack()

    best_score = tk.Label(
        best_frame,
        text="Accuracy: 98.61%   |   F1-Score: 98.61%",
        font=("Arial", 12, "bold"),
        bg=WHITE,
        fg=TEXT
    )

    best_score.pack(
        pady=(5, 15)
    )

    # Dataset information
    info = tk.Label(
        content,
        text=(
            "Dataset: 82,486 labelled emails\n"
            "Test Set: 24,746 emails\n"
            "Feature Extraction: TF-IDF\n"
            "Selected Classifier: Random Forest"
        ),
        font=("Arial", 11),
        bg=BG,
        fg=TEXT,
        justify="center"
    )

    info.pack(
        pady=15
    )


# ============================================================
# ABOUT WINDOW
# ============================================================

def show_about():

    about = tk.Toplevel(window)

    about.title("About the Project")

    about.geometry("650x500")

    about.configure(bg=BG)

    about.resizable(False, False)

    title = tk.Label(
        about,
        text="AI-BASED PHISHING EMAIL DETECTION SYSTEM",
        font=("Arial", 18, "bold"),
        bg=BG,
        fg=DARK,
        wraplength=560
    )

    title.pack(
        pady=(35, 20)
    )

    description = tk.Label(
        about,
        text=(
            "This project implements a machine-learning-based "
            "phishing email detection system.\n\n"
            "Natural Language Processing and TF-IDF feature "
            "extraction are used to transform email text into "
            "machine-readable features.\n\n"
            "Three classification algorithms were evaluated:\n"
            "• Naive Bayes\n"
            "• Logistic Regression\n"
            "• Random Forest\n\n"
            "Random Forest achieved the highest performance "
            "with an accuracy of 98.61%."
        ),
        font=("Arial", 11),
        bg=BG,
        fg=TEXT,
        justify="left",
        wraplength=560
    )

    description.pack(
        padx=40
    )

    tech = tk.Label(
        about,
        text=(
            "Technology: Python | Pandas | Scikit-learn | "
            "TF-IDF | Random Forest"
        ),
        font=("Arial", 10, "bold"),
        bg=BG,
        fg=GRAY,
        wraplength=560
    )

    tech.pack(
        pady=25
    )


# ============================================================
# MAIN WINDOW
# ============================================================

window = tk.Tk()

window.title("AI Phishing Email Detection System")

window.geometry("950x760")

window.minsize(850, 650)

window.configure(bg=BG)


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    window,
    bg=DARK,
    height=120
)

header.pack(
    fill="x"
)

title_label = tk.Label(
    header,
    text="AI PHISHING EMAIL DETECTOR",
    font=("Arial", 25, "bold"),
    fg=WHITE,
    bg=DARK
)

title_label.pack(
    pady=(22, 5)
)

subtitle_label = tk.Label(
    header,
    text="Machine Learning Based Email Security Analysis",
    font=("Arial", 12),
    fg="#d5d8dc",
    bg=DARK
)

subtitle_label.pack()


# ============================================================
# MENU BAR
# ============================================================

menu_frame = tk.Frame(
    window,
    bg=WHITE,
    height=50
)

menu_frame.pack(
    fill="x"
)

performance_button = tk.Button(
    menu_frame,
    text="📊 Model Performance",
    command=show_performance,
    font=("Arial", 10, "bold"),
    bg=WHITE,
    fg=TEXT,
    relief="flat",
    padx=15,
    pady=8,
    cursor="hand2"
)

performance_button.pack(
    side="left",
    padx=15
)

about_button = tk.Button(
    menu_frame,
    text="ℹ About Project",
    command=show_about,
    font=("Arial", 10, "bold"),
    bg=WHITE,
    fg=TEXT,
    relief="flat",
    padx=15,
    pady=8,
    cursor="hand2"
)

about_button.pack(
    side="left"
)


# ============================================================
# MAIN CONTENT
# ============================================================

content = tk.Frame(
    window,
    bg=BG
)

content.pack(
    fill="both",
    expand=True,
    padx=45,
    pady=25
)


# ============================================================
# EMAIL INPUT
# ============================================================

email_title = tk.Label(
    content,
    text="EMAIL CONTENT",
    font=("Arial", 14, "bold"),
    bg=BG,
    fg=DARK
)

email_title.pack(
    anchor="w"
)

email_box = tk.Text(
    content,
    height=11,
    font=("Arial", 12),
    wrap="word",
    relief="solid",
    bd=1,
    padx=10,
    pady=10
)

email_box.pack(
    fill="x",
    pady=(8, 12)
)


# ============================================================
# EXAMPLES
# ============================================================

example_frame = tk.Frame(
    content,
    bg=BG
)

example_frame.pack(
    fill="x"
)

phishing_button = tk.Button(
    example_frame,
    text="Load Phishing Example",
    command=phishing_example,
    font=("Arial", 10),
    padx=12,
    pady=7,
    cursor="hand2"
)

phishing_button.pack(
    side="left",
    padx=(0, 10)
)

legitimate_button = tk.Button(
    example_frame,
    text="Load Legitimate Example",
    command=legitimate_example,
    font=("Arial", 10),
    padx=12,
    pady=7,
    cursor="hand2"
)

legitimate_button.pack(
    side="left"
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

analyze_button = tk.Button(
    content,
    text="🔍  ANALYZE EMAIL",
    command=analyze_email,
    font=("Arial", 15, "bold"),
    bg=DARK,
    fg=WHITE,
    padx=35,
    pady=12,
    cursor="hand2"
)

analyze_button.pack(
    pady=18
)


# ============================================================
# RESULT PANEL
# ============================================================

result_frame = tk.Frame(
    content,
    bg=WHITE,
    relief="solid",
    bd=1
)

result_frame.pack(
    fill="x"
)

result_label = tk.Label(
    result_frame,
    text="Waiting for analysis...",
    font=("Arial", 21, "bold"),
    bg=WHITE,
    fg=TEXT
)

result_label.pack(
    pady=(18, 8)
)

risk_label = tk.Label(
    result_frame,
    text="Enter an email and click ANALYZE EMAIL.",
    font=("Arial", 12),
    bg=WHITE,
    fg=GRAY,
    justify="center"
)

risk_label.pack(
    pady=(0, 8)
)

model_label = tk.Label(
    result_frame,
    text="Analysis completed using Random Forest + TF-IDF",
    font=("Arial", 10),
    bg=WHITE,
    fg=GRAY
)

model_label.pack(
    pady=(0, 18)
)


# ============================================================
# PROJECT STATISTICS
# ============================================================

stats_frame = tk.Frame(
    content,
    bg=BG
)

stats_frame.pack(
    fill="x",
    pady=18
)

stats = [
    ("DATASET", "82,486"),
    ("TEST SET", "24,746"),
    ("ACCURACY", "98.61%"),
    ("MODEL", "RANDOM FOREST")
]

for heading, value in stats:

    card = tk.Frame(
        stats_frame,
        bg=WHITE,
        relief="solid",
        bd=1
    )

    card.pack(
        side="left",
        fill="both",
        expand=True,
        padx=4
    )

    heading_label = tk.Label(
        card,
        text=heading,
        font=("Arial", 8, "bold"),
        bg=WHITE,
        fg=GRAY
    )

    heading_label.pack(
        pady=(10, 2)
    )

    value_label = tk.Label(
        card,
        text=value,
        font=("Arial", 12, "bold"),
        bg=WHITE,
        fg=DARK
    )

    value_label.pack(
        pady=(0, 10)
    )


# ============================================================
# CLEAR BUTTON
# ============================================================

clear_button = tk.Button(
    content,
    text="Clear",
    command=clear_email,
    font=("Arial", 10),
    padx=25,
    pady=6,
    cursor="hand2"
)

clear_button.pack(
    pady=2
)


# ============================================================
# FOOTER
# ============================================================

footer = tk.Label(
    window,
    text="AI-Based Phishing Email Detection System | Research Prototype",
    font=("Arial", 9),
    bg=DARK,
    fg="#d5d8dc",
    pady=8
)

footer.pack(
    fill="x"
)


# ============================================================
# START APPLICATION
# ============================================================

window.mainloop()