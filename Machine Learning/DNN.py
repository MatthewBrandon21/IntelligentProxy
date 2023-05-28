# first neural network with keras tutorial
from numpy import loadtxt
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
import numpy as np

def StringToBytes(data):
    sum = 0
    arrbytes = bytes(data, 'utf-8')
    for i in arrbytes:
        sum = sum + i
    return(sum)

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
                  "dataset/dataset_UDP2.csv",]

features, labels = [], []

for fname in training_files:
    meal = open(fname, "rt")
    for line in meal:
        data_list = line.rsplit(",")
        if(len(data_list) != 36):
            print("error data")
        else:
            data_list[27] = StringToBytes(data_list[27])
            for i in range(len(data_list)):
                if data_list[i] == "nan":
                    data_list[i] = 0
            data_list[(len(data_list)-1)]=data_list[(len(data_list)-1)].replace('\n', '')
            features.append(data_list[:(len(data_list)-1)])
            labels.append(data_list[(len(data_list)-1)])
    meal.close()

X = features
y = np.asarray(labels).astype('float32').reshape((-1,1))
# define the keras model
model = Sequential()
model.add(Dense(12, input_shape=(35,), activation='relu'))
model.add(Dense(8, activation='relu'))
model.add(Dense(6, activation='sigmoid'))
# compile the keras model
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
# fit the keras model on the dataset
model.fit(X, y, epochs=150, batch_size=10)
# evaluate the keras model
_, accuracy = model.evaluate(X, y)
print('Accuracy: %.2f' % (accuracy*100))