import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score

df = pd.read_csv("validation_results_output.csv")
y_true = df["is_anomaly"].astype(int)
y_pred = df["AI_Prediction"].astype(int)

cm = confusion_matrix(y_true, y_pred)
TN, FP, FN, TP = cm.ravel()

acc  = accuracy_score(y_true, y_pred) * 100
prec = precision_score(y_true, y_pred, zero_division=0) * 100
rec  = recall_score(y_true, y_pred, zero_division=0) * 100

lines = [
    f"Total samples : {len(df)}",
    f"True anomalies: {int(y_true.sum())}",
    f"Pred anomalies: {int(y_pred.sum())}",
    f"TP={TP}  FP={FP}  TN={TN}  FN={FN}",
    f"Accuracy  = {acc:.4f}%",
    f"Precision = {prec:.4f}%",
    f"Recall    = {rec:.4f}%",
]
for l in lines:
    print(l)

with open("metrics_output.txt", "w") as f:
    f.write("\n".join(lines) + "\n")

print("Written to metrics_output.txt")
