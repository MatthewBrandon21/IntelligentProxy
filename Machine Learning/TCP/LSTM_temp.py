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

import joblib

def StringToBytes(data):
    sum = 0
    arrbytes = bytes(data, 'utf-8')
    for i in arrbytes:
        sum = sum + i
    return(sum)

number_of_samples = 50000

data_attack_1 = pd.read_csv('Dataset/dataset_tcp_timeseries_attack_1.csv')
data_attack_2 = pd.read_csv('Dataset/dataset_tcp_timeseries_attack_2.csv')
data_normal_1 = pd.read_csv('Dataset/dataset_tcp_timeseries_normal_1.csv')
data_normal_2 = pd.read_csv('Dataset/dataset_tcp_timeseries_normal_2.csv')
data_normal_3 = pd.read_csv('Dataset/dataset_tcp_timeseries_normal_3.csv')

data_normal_1.columns=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len', 'label']
data_normal_2.columns=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len', 'label']
data_normal_3.columns=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len', 'label']
data_attack_1.columns=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len', 'label']
data_attack_2.columns=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len', 'label']

features=['timestamp', 'port_src', 'port_dest',
       'seq', 'ack', 'dataofs', 'reserved', 'flags',
       'window', 'chksum', 'urgptr', 'payload_len']

X_normal_1= data_normal_1[features].values
X_normal_2= data_normal_2[features].values
X_normal_3= data_normal_3[features].values
X_attack_1= data_attack_1[features].values
X_attack_2= data_attack_2[features].values
Y_normal_1= data_normal_1['label']
Y_normal_2= data_normal_2['label']
Y_normal_3= data_normal_3['label']
Y_attack_1= data_attack_1['label']
Y_attack_2= data_attack_2['label']
X=np.concatenate((X_normal_1,X_normal_2,X_normal_3,X_attack_1,X_attack_2))
Y=np.concatenate((Y_normal_1,Y_normal_2,Y_normal_3,Y_attack_1,Y_attack_2))

for i in range(len(X)):
    X[i][7] = StringToBytes(str(X[i][7]))

scalar = StandardScaler(copy=True, with_mean=True, with_std=True)
scalar.fit(X)
X = scalar.transform(X)

joblib.dump(scalar, 'scaler.save') 