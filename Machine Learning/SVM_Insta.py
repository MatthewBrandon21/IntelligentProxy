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

    for fname in training_files:
        meal = open(fname, "rt")
        for line in meal:
            data_list = line.rsplit(",")
            if(len(data_list) != 36):
                print("error data")
            else:
                data_list[27] = len(data_list[27])
                for i in range(len(data_list)):
                    if data_list[i] == "nan":
                        data_list[i] = 0
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

    SEED = 42
    features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.20, stratify=labels, random_state = 20)

    # Feature scaling (or standardization)
    sc = StandardScaler()
    X_train = sc.fit_transform(features_train)
    X_test = sc.transform(features_test)

    print(features_train)
    print(X_train)

    svm_inst.fit(features_train, labels_train)
    # svm_inst.fit(X_train, labels_train)
    print("Success Training")

    labels_pred = svm_inst.predict(features_test)
    # labels_pred = svm_inst.predict(X_test)
    print("Success Evaluation")

    cm = confusion_matrix(labels_test,labels_pred)
    sns.heatmap(cm, annot=True, fmt='d').set_title('Confusion matrix of linear SVM') # fmt='d' formats the numbers as digits, which means integers

    print(labels_pred)
    print(labels_test)
    print(cm)

    print(classification_report(labels_test,labels_pred))

features, labels = [], []
svm_inst = svm.SVC(kernel='poly', degree=3, C=1)
# svm_inst = svm.SVC(kernel = 'linear', random_state=0)
training_files = [
                "dataset/dataset_HTTP.csv",
                  "dataset/dataset_HTTP_TCP.csv",
                #   "dataset/dataset_ICMP.csv",
                #   "dataset/dataset_normal_icmp.csv",
                  "dataset/dataset_normal_tcp.csv",
                #   "dataset/dataset_normal_udp.csv",
                #   "dataset/dataset_normal_udp_video.csv",
                  "dataset/dataset_SYN_TCP.csv",
                  "dataset/dataset_TCP.csv",
                #   "dataset/dataset_UDP.csv",
                #   "dataset/dataset_UDP2.csv",
                  ]
train_svm()

time_start = time.perf_counter()
result = svm_inst.predict([X_test[2]])[0]
print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(f"Correct result : {labels_test[2]}")
print(f"Predicted result : {result}")

#Save the model
filename = 'finalized_model.sav'
joblib.dump(svm_inst, filename)

# Visualising the Training set results
# X_set, y_set = X_train, labels_train
# X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
#                     np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
# plt.contourf(X1, X2, svm_inst.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
#             alpha = 0.75, cmap = ListedColormap(('red', 'green')))
# plt.xlim(X1.min(), X1.max())
# plt.ylim(X2.min(), X2.max())
# for i, j in enumerate(np.unique(y_set)):
#    plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
#                c = ListedColormap(('red', 'green'))(i), label = j)
# plt.title('SVM (Training set)')
# plt.xlabel('Data')
# plt.ylabel('Label')
# plt.legend()
# plt.show()

# Visualising the Test set results
# X_set, y_set = X_test, labels_test
# X1, X2 = np.meshgrid(np.arange(start = X_set[:, 18].min() - 1, stop = X_set[:, 35].max() + 1, step = 0.01),
#                     np.arange(start = X_set[:, 18].min() - 1, stop = X_set[:, 35].max() + 1, step = 0.01))
# plt.contourf(X1, X2, svm_inst.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
#             alpha = 0.75, cmap = ListedColormap(('red', 'green')))
# plt.xlim(X1.min(), X1.max())
# plt.ylim(X2.min(), X2.max())
# for i, j in enumerate(np.unique(y_set)):
#    plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
#                c = ListedColormap(('red', 'green'))(i), label = j)
# plt.title('SVM (Test set)')
# plt.xlabel('Data')
# plt.ylabel('Label')
# plt.legend()
# plt.show()