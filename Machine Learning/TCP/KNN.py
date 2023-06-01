import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier

import time

from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns

num_of_category = 2
features, labels = [], []
training_files = ["Dataset/dataset_tcp_attack_1.csv",
                  "Dataset/dataset_tcp_attack_2.csv",
                  "Dataset/dataset_tcp_normal_1.csv",
                  "Dataset/dataset_tcp_normal_2.csv",
                  "Dataset/dataset_tcp_normal_3.csv"]

def scrape_data():
    global training_files
    global features
    global labels
    global num_of_category

    for fname in training_files:
        meal = open(fname, "rt")
        for line in meal:
            data_list = line.rsplit(",")
            if(len(data_list) != 15):
                print("error data")
            else:
                data_list[(len(data_list)-1)]=data_list[(len(data_list)-1)].replace('\n', '')
                features.append(data_list[:(len(data_list)-1)])
                labels.append(data_list[(len(data_list)-1)])
            features.append(data_list[:(len(data_list)-1)])
            labels.append(data_list[(len(data_list)-1)])
        meal.close()
    print("Features first and last entries:\n\t", end = "")
    print(features[:1] + features[(len(features)-1):])
    print("Labels first and last entries:\n\t", end = "")
    print(labels[:1] + labels[(len(features)-1):])
    features_train, features_test, labels_train, labels_test = train_test_split(features, labels, stratify=labels, test_size = 0.20, random_state = 20)
    return features_train, labels_train, features_test, labels_test

data_train, label_train, data_eval, label_eval = scrape_data()

scaler = StandardScaler()
x_train = scaler.fit_transform(data_train)
x_test = scaler.transform(data_eval)
y_train = np.array(label_train)
y_test = np.array(label_eval)

knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(x_train, y_train)
y_pred_knn = knn_model.predict(x_test)
print((accuracy_score(y_pred_knn,y_test)) * 100, "%")

labels_pred = knn_model.predict(x_test)
cm = confusion_matrix(y_test,labels_pred)
sns.heatmap(cm, annot=True, fmt='d').set_title('Confusion matrix of linear SVM') # fmt='d' formats the numbers as digits, which means integers
print(cm)
print(classification_report(y_test,labels_pred))

time_start = time.perf_counter()
data = scaler.transform([data_eval[3]])
result = knn_model.predict([data[0]])[0]

print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(f"Correct result : {label_eval[3]}")
print(f"Predicted result : {result}")