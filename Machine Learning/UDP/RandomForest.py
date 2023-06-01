import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns

import time

num_of_category = 2
features, labels = [], []
training_files = ["Dataset/dataset_udp_attack_1.csv",
                  "Dataset/dataset_udp_attack_2.csv",
                  "Dataset/dataset_udp_normal_1.csv",
                  "Dataset/dataset_udp_normal_2.csv"]

def scrape_data():
    global training_files
    global features
    global labels
    global num_of_category

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

svm_model = SVC(kernel = 'linear', random_state=0)
svm_model.fit(x_train, y_train)
y_pred_svm = svm_model.predict(x_test)
print((accuracy_score(y_pred_svm,y_test)) * 100, "%")

knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(x_train, y_train)
y_pred_knn = knn_model.predict(x_test)
print((accuracy_score(y_pred_knn,y_test)) * 100, "%")

gaussian_model = GaussianNB()
gaussian_model.fit(x_train, y_train)
y_pred_gaussian = gaussian_model.predict(x_test)
print((accuracy_score(y_pred_gaussian,y_test)) * 100, "%")

train_x, val_x, train_y, val_y = train_test_split(x_train, y_train, stratify=y_train, test_size=0.20, random_state=20)

model1 = SVC(kernel = 'linear', random_state=0)
model1.fit(train_x, train_y)
y_val_pred1 = model1.predict(val_x)
y_val_pred1 = pd.DataFrame(y_val_pred1)
y_test_pred1 = model1.predict(x_test)
y_test_pred1 = pd.DataFrame(y_test_pred1)

model2 = KNeighborsClassifier(n_neighbors=5)
model2.fit(train_x, train_y)
y_val_pred2 = model2.predict(val_x)
y_val_pred2 = pd.DataFrame(y_val_pred2)
y_test_pred2 = model2.predict(x_test)
y_test_pred2 = pd.DataFrame(y_test_pred2)

model3 = GaussianNB()
model3.fit(train_x, train_y)
y_val_pred3 = model3.predict(val_x)
y_val_pred3 = pd.DataFrame(y_val_pred3)
y_test_pred3 = model3.predict(x_test)
y_test_pred3 = pd.DataFrame(y_test_pred3)

val_input = pd.concat([pd.DataFrame(val_x), y_val_pred1, y_val_pred2, y_val_pred3], axis=1)
test_input = pd.concat([pd.DataFrame(x_test), y_test_pred1, y_test_pred2, y_test_pred3], axis=1)

model_final = RandomForestClassifier(n_estimators=200)
model_final.fit(val_input, val_y)

print((model_final.score(test_input, y_test)) * 100, "%")

# print(label_eval)

labels_pred = model_final.predict(test_input)
cm = confusion_matrix(y_test,labels_pred)
sns.heatmap(cm, annot=True, fmt='d').set_title('Confusion matrix of linear SVM') # fmt='d' formats the numbers as digits, which means integers
print(cm)
print(classification_report(y_test,labels_pred))

time_start = time.perf_counter()
data = scaler.transform([data_eval[3]])
y_val_pred1_test = pd.DataFrame(model1.predict([data[0]]))
y_val_pred2_test = pd.DataFrame(model2.predict([data[0]]))
y_val_pred3_test = pd.DataFrame(model3.predict([data[0]]))
val_input_test = pd.concat([pd.DataFrame([data[0]]), y_val_pred1_test, y_val_pred2_test, y_val_pred3_test], axis=1)
print(val_input_test)
print(np.shape(val_input_test))
result = model_final.predict(val_input_test)[0]

print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(f"Correct result : {label_eval[3]}")
print(f"Predicted result : {result}")