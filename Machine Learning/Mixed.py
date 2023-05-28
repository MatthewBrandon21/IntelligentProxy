import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier

num_of_category = 6
features, labels = [], []
training_files = ["dataset/dataset_HTTP.csv",
                  "dataset/dataset_HTTP_TCP.csv",
                  "dataset/dataset_ICMP.csv",
                  "dataset/dataset_normal_icmp.csv",
                  "dataset/dataset_normal_tcp.csv",
                  "dataset/dataset_normal_udp.csv",
                  "dataset/dataset_normal_udp_video.csv",
                  "dataset/dataset_SYN_TCP.csv",
                  "dataset/dataset_TCP.csv",
                  "dataset/dataset_UDP.csv",
                  "dataset/dataset_UDP2.csv"]

def scrape_data():
    global training_files
    global features
    global labels
    global num_of_category

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
            features.append(data_list[:(len(data_list)-1)])
            labels.append(data_list[(len(data_list)-1)])
        meal.close()
    print("Features first and last entries:\n\t", end = "")
    print(features[:1] + features[(len(features)-1):])
    print("Labels first and last entries:\n\t", end = "")
    print(labels[:1] + labels[(len(features)-1):])
    SEED = 42
    features_train, features_test, labels_train, labels_test = train_test_split(features, labels, stratify=labels, test_size = 0.20, random_state = 0)

    return features_train, labels_train, features_test, labels_test

data_train, label_train, data_eval, label_eval = scrape_data()

scaler = StandardScaler()
x_train = scaler.fit_transform(data_train)
x_test = scaler.transform(data_eval)
y_train = np.array(label_train)
y_test = np.array(label_eval)

svm_model = SVC(kernel='sigmoid', gamma='auto')
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

train_x, val_x, train_y, val_y = train_test_split(x_train, y_train, stratify=y_train, test_size=0.20, random_state=0)

randvar1 = "timestamp_std"
randvar2 = "no_thread_std"
randvar3 = "msg_time_std"
randvar4 = "connection_time_std"
randvar5 = "connection_time_sum"
randvar6 = "connection_time_avg"
randvar7 = "icmp_type_std"
randvar8 = "icmp_code_std"
randvar9 = "icmp_checksum_std"
randvar10 = "icmp_p_id_std"
randvar11 = "sequence_std"
randvar12 = "r_packets_std"
randvar13 = "r_packets_sum"
randvar14 = "r_bytes_std"
randvar15 = "r_bytes_sum"
randvar16 = "r_bytes_avg"
randvar17 = "n_packets_std"
randvar18 = "n_packets_sum"
randvar19 = "n_bytes_std"
randvar20 = "n_bytes_sum"
randvar21 = "n_bytes_avg"
randvar22 = "port_src_std"
randvar23 = "ip_dest_std"
randvar24 = "port_dest_std"
randvar25 = "tcp_url_std"
randvar26 = "connection_state_std"
randvar27 = "connection_state_sum"
randvar28 = "protocol"
randvar29 = "number_of_unique_url"
randvar30 = "number_of_unique_src_port"
randvar31 = "number_of_unique_dest_port"
randvar32 = "number_of_unique_dest_ipaddress"
randvar33 = "total_connection"
randvar34 = "rate_connection"
randvar35 = "connection_timeout"

data_columns = [randvar1,randvar2,randvar3,randvar4,randvar5,randvar6,
                randvar7, randvar8, randvar9, randvar10, randvar11,
                randvar12, randvar13, randvar14, randvar15, randvar16,
                randvar17, randvar18, randvar19, randvar20, randvar21,
                randvar22, randvar23, randvar24, randvar25, randvar26,
                randvar27, randvar28, randvar29, randvar30, randvar31,
                randvar32, randvar33, randvar34, randvar35]

model1 = SVC(kernel='sigmoid', gamma='auto')
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

val_input = pd.concat([pd.DataFrame(val_x, columns=data_columns), y_val_pred1, y_test_pred2, y_val_pred3], axis=1)
test_input = pd.concat([pd.DataFrame(x_test, columns=data_columns), y_test_pred1, y_test_pred2, y_test_pred3], axis=1)

model_final = RandomForestClassifier(n_estimators=200)
model_final.fit(val_input, val_y)

print((model_final.score(test_input, y_test)) * 100, "%")