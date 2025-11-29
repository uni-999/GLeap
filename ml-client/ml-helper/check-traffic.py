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
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import requests
from pathlib import Path 

#Конфигурация
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

def main():
    print("=== Обучение/Тест модели обнаружения сетевых атак (traffic detector) ===")
    csv_path = findFirstCsv()
    if csv_path:
        df = loadDataset(csv_path)
        label_col = guessLabelToColumn(df)
        print("Done")
    
    else:
        print("None")

if __name__ == "__main__":
    main()
