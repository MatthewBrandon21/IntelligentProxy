import numpy as np
from matplotlib import pyplot as plt
from keras.layers import Dense, Dropout
from keras.models import Sequential
from keras.models import load_model
from keras.callbacks import TensorBoard
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split

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
                data_list[(len(data_list)-1)]=int(data_list[(len(data_list)-1)].replace('\n', ''))
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
    features_train, features_test, labels_train, labels_test = train_test_split(features, labels, test_size = 0.20, stratify=labels, random_state = 0)
    
    labels_train = to_categorical(labels_train, num_of_category)
    labels_test = to_categorical(labels_test, num_of_category)

    return np.asarray(features_train), np.asarray(labels_train), np.asarray(features_test), np.asarray(labels_test)

def generate_model(shape):
    model = Sequential()

    model.add(Dense(35, input_dim=shape, kernel_initializer='uniform', activation='relu'))
    model.add(Dropout(0.4))
    model.add(Dense(10, activation='relu'))
    model.add(Dropout(0.4))
    model.add(Dense(10, activation='relu'))
    model.add(Dropout(0.4))
    model.add(Dense(64, activation='relu'))
    model.add(Dropout(0.4))
    model.add(Dense(6, activation='softmax'))
    print(model.summary())

    return model

data_train, label_train, data_eval, label_eval = scrape_data()

model = generate_model(len(data_train[0]))
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

tensorboard = TensorBoard(log_dir='logs/', histogram_freq=0, write_graph=True, write_images=True)

history = model.fit(data_train, label_train, validation_data=(data_eval, label_eval), epochs=2, callbacks=[tensorboard])
loss_history = history.history["loss"]

print(model.evaluate(data_eval, label_eval))
print(model.evaluate(data_train, label_train))