import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

import seaborn as sns; sns.set()

from keras.models import Sequential, load_model
from keras.layers import Dense, LSTM, Bidirectional
from keras.utils import plot_model
from keras.utils.np_utils import to_categorical
from keras.utils import np_utils

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import confusion_matrix

from keras.models import load_model
import joblib
import time

def StringToBytes(data):
    sum = 0
    arrbytes = bytes(data, 'utf-8')
    for i in arrbytes:
        sum = sum + i
    return(sum)

number_of_samples = 101

data_normal_1 = pd.read_csv('Dataset/dataset_tcp_timeseries_attack_1.csv', nrows = number_of_samples)

data_normal_1.columns=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len', 'label']

features=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len']

X_normal_1= data_normal_1[features].values
Y_normal_1= data_normal_1['label']
X=X_normal_1
Y=Y_normal_1

for i in range(len(X)):
    X[i][7] = StringToBytes(str(X[i][7]))

scalar = joblib.load('scaler_lstm_tcp.save') 
model = load_model('brnn_model_100_step.h5')

time_start = time.perf_counter()
X = scalar.transform(X)

print(np.shape(X))
print(np.shape(Y))

features = len(X[0])
samples = X.shape[0]
train_len = 100
input_len = samples - train_len
I = np.zeros((samples - train_len, train_len, features))

for i in range(input_len):
    temp = np.zeros((train_len, features))
    for j in range(i, i + train_len - 1):
        temp[j-i] = X[j]
    I[i] = temp

print(I.shape)

predict = model.predict(I[:100], verbose=1)
print(f"Time elapse for prediction : {time.perf_counter() - time_start}")
print(predict)