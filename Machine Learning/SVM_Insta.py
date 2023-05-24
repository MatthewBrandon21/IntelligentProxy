# pip3 install sklearn
# pip3 install numpy
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.externals import joblib
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
            for i in range(len(data_list)):
                if i < 2:
                    data_list[i] = float(data_list[i])
                else:
                    data_list[i] = int(data_list[i])
            features.append(data_list[:(len(data_list)-1)])
            labels.append(data_list[(len(data_list)-1)])
        meal.close()
    print("Features first and last entries:\n\t", end = "")
    print(features[:1] + features[(len(features)-2):])
    print("Labels first and last entries:\n\t", end = "")
    print(labels[:1] + labels[(len(features)-2):])

    SEED = 42
    features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.20, random_state = SEED)

    # Feature scaling (or standardization)
    sc = StandardScaler()
    X_train = sc.fit_transform(features_train)
    X_test = sc.transform(features_test)

    # svm_inst.fit(features_train, labels_train)
    svm_inst.fit(X_train, labels_train)

    # labels_pred = svm_inst.predict(features_test)
    labels_pred = svm_inst.predict(X_test)

    cm = confusion_matrix(labels_test,labels_pred)
    sns.heatmap(cm, annot=True, fmt='d').set_title('Confusion matrix of linear SVM') # fmt='d' formats the numbers as digits, which means integers

    print(labels_pred)
    print(cm)

    print(classification_report(labels_test,labels_pred))

features, labels = [], []
# svm_inst = svm.SVC(kernel = 'linear')
svm_inst = svm.SVC(kernel = 'linear', random_state=0)
training_files = ["training_datasets/ICMP_data_class_0.csv", "training_datasets/ICMP_data_class_1.csv"]
train_svm()

time_start = time.perf_counter()
result = svm_inst.predict([features[0]])[0]
print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(result)

#Save the model
filename = 'finalized_model.sav'
joblib.dump(svm_inst, filename)

# Visualising the Training set results
X_set, y_set = X_train, labels_train
X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                    np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
plt.contourf(X1, X2, svm_inst.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
            alpha = 0.75, cmap = ListedColormap(('red', 'green')))
plt.xlim(X1.min(), X1.max())
plt.ylim(X2.min(), X2.max())
for i, j in enumerate(np.unique(y_set)):
   plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
               c = ListedColormap(('red', 'green'))(i), label = j)
plt.title('SVM (Training set)')
plt.xlabel('Data')
plt.ylabel('Label')
plt.legend()
plt.show()

# Visualising the Test set results
X_set, y_set = X_test, labels_test
X1, X2 = np.meshgrid(np.arange(start = X_set[:, 0].min() - 1, stop = X_set[:, 0].max() + 1, step = 0.01),
                    np.arange(start = X_set[:, 1].min() - 1, stop = X_set[:, 1].max() + 1, step = 0.01))
plt.contourf(X1, X2, svm_inst.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape),
            alpha = 0.75, cmap = ListedColormap(('red', 'green')))
plt.xlim(X1.min(), X1.max())
plt.ylim(X2.min(), X2.max())
for i, j in enumerate(np.unique(y_set)):
   plt.scatter(X_set[y_set == j, 0], X_set[y_set == j, 1],
               c = ListedColormap(('red', 'green'))(i), label = j)
plt.title('SVM (Test set)')
plt.xlabel('Data')
plt.ylabel('Label')
plt.legend()
plt.show()