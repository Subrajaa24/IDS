import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# 1. Load dataset
data = pd.read_csv("dataset/intrusion_data.csv")

# 2. Define features (These columns must exist in your CSV)
features = [
    "sbytes", "dbytes", "spkts", "dpkts",
    "rate", "sttl", "dttl",
    "sload", "dload", "smean", "dmean"
]

X = data[features].fillna(0)
y = data["label"]

# 3. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 4. Initialize XGBoost
model = XGBClassifier(
    n_estimators=400,
    max_depth=8,
    learning_rate=0.08,
    scale_pos_weight=(y == 0).sum() / (y == 1).sum(),
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

# 5. Train
print("🚀 Training model...")
model.fit(X_train, y_train)

# 6. Evaluate
y_pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

# 7. Save model
joblib.dump(model, "model.pkl")
print("\n💾 Model saved as model.pkl")