import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import ConfusionMatrixDisplay


# ============================================================
# ACTUAL MODEL RESULTS FROM THE EXPERIMENT
# ============================================================

models = [
    "Naive Bayes",
    "Logistic Regression",
    "Random Forest"
]

accuracy = [
    0.955023,
    0.980037,
    0.986139
]

precision = [
    0.956517,
    0.980053,
    0.986141
]

recall = [
    0.955023,
    0.980037,
    0.986139
]

f1_score = [
    0.955038,
    0.980034,
    0.986138
]


# ============================================================
# GRAPH 1 — MODEL PERFORMANCE COMPARISON
# ============================================================

x = np.arange(len(models))
width = 0.2

plt.figure(figsize=(10, 6))

plt.bar(
    x - 1.5 * width,
    accuracy,
    width,
    label="Accuracy"
)

plt.bar(
    x - 0.5 * width,
    precision,
    width,
    label="Precision"
)

plt.bar(
    x + 0.5 * width,
    recall,
    width,
    label="Recall"
)

plt.bar(
    x + 1.5 * width,
    f1_score,
    width,
    label="F1-Score"
)

plt.xticks(x, models)
plt.ylabel("Score")
plt.xlabel("Machine Learning Model")
plt.title("Machine Learning Model Performance Comparison")
plt.ylim(0.90, 1.00)
plt.legend()

plt.tight_layout()

plt.savefig(
    "model_performance_comparison.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ============================================================
# GRAPH 2 — CONFUSION MATRIX
# ============================================================

confusion_matrix = np.array([
    [11692, 187],
    [156, 12711]
])

plt.figure(figsize=(7, 6))

disp = ConfusionMatrixDisplay(
    confusion_matrix=confusion_matrix,
    display_labels=["Class 0", "Class 1"]
)

disp.plot()

plt.title("Random Forest Confusion Matrix")

plt.tight_layout()

plt.savefig(
    "random_forest_confusion_matrix.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


print("\n==============================================")
print("GRAPHS CREATED SUCCESSFULLY")
print("==============================================")

print("\nCreated files:")

print("1. model_performance_comparison.png")
print("2. random_forest_confusion_matrix.png")