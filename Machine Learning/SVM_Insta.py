# pip3 install sklearn
# pip3 install numpy
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import time

def train_svm():
    global svm_inst
    global training_files
    global features
    global labels

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

    svm_inst.fit(features_train, labels_train)

    labels_pred = svm_inst.predict(features_test)

    cm = confusion_matrix(labels_test,labels_pred)
    sns.heatmap(cm, annot=True, fmt='d').set_title('Confusion matrix of linear SVM') # fmt='d' formats the numbers as digits, which means integers

    print(classification_report(labels_test,labels_pred))

features, labels = [], []
svm_inst = svm.SVC(kernel = 'linear')
training_files = ["training_datasets/ICMP_data_class_0.csv", "training_datasets/ICMP_data_class_1.csv"]
train_svm()

time_start = time.perf_counter()
result = svm_inst.predict([features[0]])[0]
print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(result)