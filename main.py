import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

print("=" * 70)
print("AI-BASED PHISHING EMAIL DETECTION SYSTEM")
print("COMPARATIVE MACHINE LEARNING EXPERIMENT")
print("=" * 70)

# ============================================================
# 1. LOAD DATASET
# ============================================================

print("\n[1] Loading dataset...")

df = pd.read_csv("phishing_email.csv")

print("Dataset loaded successfully.")
print("Total records:", len(df))

print("\nColumns:")
print(df.columns.tolist())


# ============================================================
# 2. DATA CLEANING
# ============================================================

print("\n[2] Cleaning dataset...")

df = df[["text_combined", "label"]]

df = df.dropna(subset=["text_combined", "label"])

df["text_combined"] = df["text_combined"].astype(str)

print("Records after cleaning:", len(df))

print("\nClass distribution:")
print(df["label"].value_counts())


# ============================================================
# 3. INPUT AND TARGET
# ============================================================

X_text = df["text_combined"]
y = df["label"]


# ============================================================
# 4. TRAIN / TEST SPLIT
# ============================================================

print("\n[3] Creating training and testing datasets...")

X_train_text, X_test_text, y_train, y_test = train_test_split(
    X_text,
    y,
    test_size=0.30,
    random_state=42,
    stratify=y
)

print("Training records:", len(X_train_text))
print("Testing records:", len(X_test_text))


# ============================================================
# 5. TF-IDF FEATURE EXTRACTION
# ============================================================

print("\n[4] Applying TF-IDF feature extraction...")

vectorizer = TfidfVectorizer(
    stop_words="english",
    ngram_range=(1, 2),
    max_features=5000
)

X_train = vectorizer.fit_transform(X_train_text)

X_test = vectorizer.transform(X_test_text)

print("TF-IDF completed.")
print("Training feature matrix:", X_train.shape)
print("Testing feature matrix:", X_test.shape)


# ============================================================
# 6. DEFINE MACHINE LEARNING MODELS
# ============================================================

models = {

    "Naive Bayes": MultinomialNB(),

    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        random_state=42
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )
}


# ============================================================
# 7. TRAIN AND EVALUATE MODELS
# ============================================================

results = {}

for model_name, model in models.items():

    print("\n" + "=" * 70)
    print("TRAINING:", model_name)
    print("=" * 70)

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    results[model_name] = {
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1-Score": f1
    }

    print("\nAccuracy :", f"{accuracy:.4f}")
    print("Precision:", f"{precision:.4f}")
    print("Recall   :", f"{recall:.4f}")
    print("F1-Score :", f"{f1:.4f}")


# ============================================================
# 8. MODEL COMPARISON
# ============================================================

print("\n")
print("=" * 70)
print("MODEL PERFORMANCE COMPARISON")
print("=" * 70)

results_df = pd.DataFrame(results).T

print(results_df.to_string())


# ============================================================
# 9. BEST MODEL
# ============================================================

best_model_name = results_df["F1-Score"].idxmax()

print("\n" + "=" * 70)
print("BEST PERFORMING MODEL")
print("=" * 70)

print("Best model:", best_model_name)

print(
    "Best F1-Score:",
    f"{results_df.loc[best_model_name, 'F1-Score']:.4f}"
)


# ============================================================
# 10. RANDOM FOREST EVALUATION
# ============================================================

print("\n")
print("=" * 70)
print("DETAILED RANDOM FOREST EVALUATION")
print("=" * 70)

rf_model = models["Random Forest"]

rf_predictions = rf_model.predict(X_test)

print("\nConfusion Matrix:")

rf_cm = confusion_matrix(
    y_test,
    rf_predictions
)

print(rf_cm)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        rf_predictions,
        zero_division=0
    )
)


# ============================================================
# 11. SAVE RANDOM FOREST MODEL
# ============================================================

print("\n")
print("=" * 70)
print("SAVING TRAINED MODEL")
print("=" * 70)

joblib.dump(
    rf_model,
    "random_forest_model.pkl"
)

joblib.dump(
    vectorizer,
    "tfidf_vectorizer.pkl"
)

print("Random Forest model saved as: random_forest_model.pkl")
print("TF-IDF vectorizer saved as: tfidf_vectorizer.pkl")


# ============================================================
# 12. NEW EMAIL PREDICTION
# ============================================================

print("\n")
print("=" * 70)
print("NEW EMAIL PREDICTION")
print("=" * 70)

test_email = input(
    "\nEnter an email message to classify:\n"
)

test_vector = vectorizer.transform(
    [test_email]
)

prediction = rf_model.predict(
    test_vector
)[0]

print("\nPrediction Result:")

if prediction == 1:
    print("⚠ PHISHING EMAIL DETECTED")
else:
    print("✓ LEGITIMATE EMAIL")


# ============================================================
# END
# ============================================================

print("\n")
print("=" * 70)
print("AI PHISHING DETECTION SYSTEM RUNNING ✔")
print("=" * 70)