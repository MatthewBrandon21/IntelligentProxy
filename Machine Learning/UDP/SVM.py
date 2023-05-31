# pip3 install sklearn
# pip3 install numpy

from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
import pandas as pd
import time

def train_svm():
    global svm_inst
    global training_files
    global features
    global labels
    global features_train
    global features_test
    global labels_train
    global labels_test
    global X_train
    global X_test
    global sc

    for fname in training_files:
        meal = open(fname, "rt")
        for line in meal:
            data_list = line.rsplit(",")
            if(len(data_list) != 9):
                print("error data")
            else:
                data_list[(len(data_list)-1)]=data_list[(len(data_list)-1)].replace('\n', '')
                features.append(data_list[:(len(data_list)-1)])
                labels.append(data_list[(len(data_list)-1)])
        meal.close()
    print(f"Size of feature dataset : {len(features)}")
    print(f"Size of feature dataset : {len(labels)}")
    print("Features first and last entries:\n\t", end = "")
    print(features[:1] + features[(len(features)-1):])
    print("Labels first and last entries:\n\t", end = "")
    print(labels[:1] + labels[(len(features)-1):])

    features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.20, stratify=labels, random_state = 20)

    # Feature scaling (or standardization)
    sc = StandardScaler()
    X_train = sc.fit_transform(features_train)
    X_test = sc.transform(features_test)

    print(features_train)
    print(X_train)

    # svm_inst.fit(features_train, labels_train)
    svm_inst.fit(X_train, labels_train)

    # labels_pred = svm_inst.predict(features_test)
    labels_pred = svm_inst.predict(X_test)

    cm = confusion_matrix(labels_test,labels_pred)
    sns.heatmap(cm, annot=True, fmt='d').set_title('Confusion matrix of linear SVM') # fmt='d' formats the numbers as digits, which means integers

    print(labels_pred)
    print(labels_test)
    print(cm)

    print(classification_report(labels_test,labels_pred))

features, labels = [], []
# svm_inst = svm.SVC(kernel='poly', degree=3, C=1)
# svm_inst = svm.SVC(kernel='sigmoid', gamma='auto')
svm_inst = svm.SVC(kernel = 'linear', random_state=0)
training_files = ["Dataset/dataset_udp_attack_1.csv",
                  "Dataset/dataset_udp_attack_2.csv",
                  "Dataset/dataset_udp_normal_1.csv",
                  "Dataset/dataset_udp_normal_2.csv"]
train_svm()

time_start = time.perf_counter()
result = svm_inst.predict([X_test[0]])[0]
print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(f"Correct result : {labels_test[0]}")
print(f"Predicted result : {result}")

time_start = time.perf_counter()
data = sc.transform([features_test[14]])
result = svm_inst.predict([data[0]])[0]
print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(f"Correct result : {labels_test[14]}")
print(f"Predicted result : {result}")

# #Save the model
# filename = 'finalized_model.sav'
# joblib.dump(svm_inst, filename)