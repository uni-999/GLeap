import os
import glob
import time
import json
import joblib
import socket
import threading
from collections import defaultdict, deque
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import requests
from pathlib import Path 

RANDOM_STATE = 42
SCRIPT_DIR = Path(__file__).parent
DATASETS_DIR = SCRIPT_DIR / "datasets" #ALLFLOWMETER_HIKARI2022.csv
MODELS_DIR = Path("models")
MODEL_FILENAME = MODELS_DIR / "traffic_detector.joblib"
DEFAULT_MODEL = "rf"
POSSIBLE_LABEL_COLS = ["label", "class", "attack", "is_attack", "malicious", "target"]

def findFirstCsv(datasetsDir=DATASETS_DIR):
    datasetsDir.mkdir(exist_ok=True)
    csvs = sorted([
        p for p in datasetsDir.iterdir()
            if p.is_file() and p.suffix.lower() == '.csv'
    ])
    return csvs[0] if csvs else None

def loadDataset(path):
    csv = pd.read_csv(path, low_memory = False, encoding='utf-8')
    return csv

def guessLabelToColumn(df: pd.DataFrame):
    for c in POSSIBLE_LABEL_COLS:
        if c in df.columns:
            return c
    for col in df.columns:
        nunq = df[col].nunique(dropna=True)
        if nunq <= 3 and df[col].dtype != float:
            return col
    return None

def splitFeatures(df: pd.DataFrame, labelCol: str):

    X = df.drop(columns=[labelCol]) if labelCol else df.copy()
    y = df[labelCol] if labelCol else None

    numericCols = X.select_dtypes(include=["number"]).columns.tolist()
    categoricalCols = X.select_dtypes(include=["object", "category", "bool"]).columns.tolist()
    for col in numericCols[:]:
        if X[col].nunique(dropna=True) <= 20:
            numericCols.remove(col)
            categoricalCols.append(col)

    print(f"[i] Числовых признаков: {len(numericCols)}, категориальных: {len(categoricalCols)}")
    return X, y, numericCols, categoricalCols


def generateSyntheticTraffic(nSamples=2000, attackRatio=0.08):
    
    n = nSamples
    protocols = ["TCP", "UDP", "ICMP"]
    ports = list(range(1, 65536))
    flagsChoices = ["S", "A", "F", "P", "SA", "PA", "FA", ""]

    rows = []
    nAttack = int(n * attackRatio)
    nBenign = n - nAttack

    for _ in range(nBenign):
        packets = np.random.poisson(lam=8) + 1
        totalBytes = max(20, int(np.random.normal(loc=1000, scale=500)))
        avgPkt = totalBytes / packets
        row = {
            "src_ip": f"192.168.{np.random.randint(0,255)}.{np.random.randint(1,255)}",
            "dst_ip": f"10.0.{np.random.randint(0,255)}.{np.random.randint(1,255)}",
            "src_port": np.random.randint(1024, 65535),
            "dst_port": np.random.choice([80, 443, 53, 22, 8080, np.random.randint(1024, 65535)]),
            "protocol": np.random.choice(protocols, p=[0.7,0.25,0.05]),
            "duration": max(0.0, np.random.exponential(scale=0.5)),
            "total_bytes": totalBytes,
            "packets": packets,
            "avg_pkt_size": avgPkt,
            "flags": np.random.choice(flagsChoices, p=[0.25,0.25,0.05,0.1,0.15,0.05,0.05,0.1]),
            "label": "benign"
        }
        rows.append(row)

    for _ in range(nAttack):
        typ = np.random.choice(["ddos","portscan","synflood","icmp_flood"])
        if typ == "ddos":
            packets = np.random.poisson(lam=200) + 10
            totalBytes = max(200, int(np.random.normal(loc=5000, scale=2000)))
            flags = np.random.choice(["S","F","SA",""])
        elif typ == "synflood":
            packets = np.random.poisson(lam=1000) + 50
            totalBytes = max(100, int(np.random.normal(loc=2000, scale=1000)))
            flags = "S"
        elif typ == "portscan":
            packets = np.random.poisson(lam=30) + 1
            totalBytes = max(50, int(np.random.normal(loc=300, scale=100)))
            flags = np.random.choice(["","S"])
        else:  # icmp
            packets = np.random.poisson(lam=300) + 5
            totalBytes = max(100, int(np.random.normal(loc=8000, scale=4000)))
            flags = ""
        avgPkt = totalBytes / max(1, packets)
        row = {
            "src_ip": f"203.0.{np.random.randint(0,255)}.{np.random.randint(1,255)}",
            "dst_ip": f"10.0.{np.random.randint(0,255)}.{np.random.randint(1,255)}",
            "src_port": np.random.randint(1, 65535),
            "dst_port": np.random.choice([80, 443, 22, 23, 3389, np.random.randint(1, 65535)]),
            "protocol": np.random.choice(protocols, p=[0.8,0.1,0.1]),
            "duration": max(0.0, np.random.exponential(scale=0.1)),
            "total_bytes": totalBytes,
            "packets": packets,
            "avg_pkt_size": avgPkt,
            "flags": flags,
            "label": "attack"
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    return df

def buildPipelineAndTrainModel(df: pd.DataFrame, labelCol: str = None, modelType=DEFAULT_MODEL):
    if labelCol is None:
        print("[i] Генерирую целевую метку по эвристике: большая частота пакетов/малый duration -> attack")
        df = df.copy()
        if "packets" not in df.columns:
            df["packets"] = np.random.poisson(lam=8, size=len(df)) + 1
        if "duration" not in df.columns:
            df["duration"] = np.abs(np.random.exponential(scale=0.5, size=len(df)))
        df["label"] = np.where((df["packets"] > df["packets"].quantile(0.98)) & (df["duration"] < df["duration"].quantile(0.2)), "attack", "benign")
        labelCol = "Lable"

    print(df["Label"].value_counts())
    print(df["attack_category"].value_counts())

    X, y, numericCols, categoricalCols = splitFeatures(df, labelCol)

    droppable = [c for c in categoricalCols if ("ip" in c.lower() or c.lower().endswith("_ip") or c.lower().endswith("ip"))]
    if droppable:
        print(f"[i] Удаляю идентификаторы: {droppable}")
        X = X.drop(columns=droppable)
        categoricalCols = [c for c in categoricalCols if c not in droppable]

    top_k = 50
    reducedCategoryMaps = {}
    for c in categoricalCols:
        topValues = X[c].value_counts().index[:top_k].tolist()
        reducedCategoryMaps[c] = set(topValues)
        X[c] = X[c].apply(lambda v: v if v in reducedCategoryMaps[c] else "OTHER")

    numericTransformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])
    categoricalTransformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="constant", fill_value="missing")),
        ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
    ])

    preprocessor = ColumnTransformer(transformers=[
        ("num", numericTransformer, numericCols),
        ("cat", categoricalTransformer, categoricalCols)
    ], remainder='drop', sparse_threshold=0)

    if modelType == "rf":
        clf = RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE, class_weight='balanced', n_jobs=-1)
    elif modelType == "logreg":
        clf = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=RANDOM_STATE)
    else:
        raise ValueError("Unknown model_type")

    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", clf)
    ])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y)

    print("Начало обучения модели...")
    pipeline.fit(X_train, y_train)
    print("Обучение завершено.")

    y_pred = pipeline.predict(X_test)
    print("Метрики на тестовой выборке:")
    print(classification_report(y_test, y_pred, digits=4))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump({
        "pipeline": pipeline,
        "numeric_cols": numericCols,
        "categorical_cols": categoricalCols,
        "reduced_category_maps": reducedCategoryMaps
    }, MODEL_FILENAME)
    print(f"Модель и pipeline сохранены в {MODEL_FILENAME}")

    return pipeline, (X_train, X_test, y_train, y_test)

def main():
    csvPath = findFirstCsv()
    if csvPath:
        df = loadDataset(csvPath)
        labelCol = "attack_category"
        pipeline, splits = buildPipelineAndTrainModel(df, labelCol=labelCol, modelType=DEFAULT_MODEL)
        print("Done")
    
    else:
        print("None")

if __name__ == "__main__":
    main()
