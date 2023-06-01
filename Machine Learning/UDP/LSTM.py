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

data_attack_1 = pd.read_csv('Dataset/dataset_udp_timeseries_attack_1.csv')
data_attack_2 = pd.read_csv('Dataset/dataset_udp_timeseries_attack_2.csv')
data_normal_1 = pd.read_csv('Dataset/dataset_udp_timeseries_normal_1.csv')
data_normal_2 = pd.read_csv('Dataset/dataset_udp_timeseries_normal_2.csv')
data_normal_3 = pd.read_csv('Dataset/dataset_udp_timeseries_normal_3.csv')

data_normal_1.columns=['timestamp', 'port_src', 'port_dest',
       'len', 'chksum', 'payload_len', 'label']
data_normal_2.columns=['timestamp', 'port_src', 'port_dest',
       'len', 'chksum', 'payload_len', 'label']
data_normal_3.columns=['timestamp', 'port_src', 'port_dest',
       'len', 'chksum', 'payload_len', 'label']
data_attack_1.columns=['timestamp', 'port_src', 'port_dest',
       'len', 'chksum', 'payload_len', 'label']
data_attack_2.columns=['timestamp', 'port_src', 'port_dest',
       'len', 'chksum', 'payload_len', 'label']

features=['timestamp', 'port_src', 'port_dest',
       'len', 'chksum', 'payload_len']

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

scalar = StandardScaler(copy=True, with_mean=True, with_std=True)
scalar.fit(X)
X = scalar.transform(X)

print(np.shape(X))
print(np.shape(Y))

features = len(X[0])
samples = X.shape[0]
train_len = 25
input_len = samples - train_len
I = np.zeros((samples - train_len, train_len, features))

for i in range(input_len):
    temp = np.zeros((train_len, features))
    for j in range(i, i + train_len - 1):
        temp[j-i] = X[j]
    I[i] = temp

print(I.shape)

X_train, X_test, Y_train, Y_test = train_test_split(I, Y[25:], test_size = 0.2)

def create_baseline():
    model = Sequential()
    
    model.add(Bidirectional(LSTM(64, activation='tanh', kernel_regularizer='l2')))
    model.add(Dense(128, activation = 'relu', kernel_regularizer='l2'))
    model.add(Dense(1, activation = 'sigmoid', kernel_regularizer='l2'))
    
    model.compile(loss = 'binary_crossentropy', optimizer = 'adam', metrics = ['accuracy'])
    
    return model

model = create_baseline()

history = model.fit(X_train, Y_train, epochs = 10,validation_split=0.2, verbose = 1)

# # Plot training & validation accuracy values
# plt.plot(history.history['acc'])
# plt.plot(history.history['val_acc'])
# plt.title('BRNN Model Accuracy')
# plt.ylabel('Accuracy')
# plt.xlabel('Epoch')
# plt.legend(['Train', 'Test'], loc='lower right')
# plt.savefig('BRNN Model Accuracy.png')
# plt.show()

# # Plot training & validation loss values
# plt.plot(history.history['loss'])
# plt.plot(history.history['val_loss'])
# plt.title('BRNN Model  Loss')
# plt.ylabel('Loss')
# plt.xlabel('Epoch')
# plt.legend(['Train', 'Test'], loc='upper left')
# plt.savefig('BRNN Model Loss.png')
# plt.show()

predict = model.predict(X_test, verbose=1)

tp = 0
tn = 0
fp = 0
fn = 0
predictn = predict.flatten().round()
predictn = predictn.tolist()
Y_testn = Y_test.tolist()
for i in range(len(Y_testn)):
  if predictn[i]==1 and Y_testn[i]==1:
    tp+=1
  elif predictn[i]==0 and Y_testn[i]==0:
    tn+=1
  elif predictn[i]==0 and Y_testn[i]==1:
    fp+=1
  elif predictn[i]==1 and Y_testn[i]==0:
    fn+=1

to_heat_map =[[tn,fp],[fn,tp]]
to_heat_map = pd.DataFrame(to_heat_map, index = ["Attack","Normal"],columns = ["Attack","Normal"])
ax = sns.heatmap(to_heat_map,annot=True, fmt="d")

figure = ax.get_figure()    
figure.savefig('confusion_matrix_BRNN.png', dpi=400)

model.save('brnn_model.h5')
joblib.dump(scalar, 'scaler.save') 

scores = model.evaluate(X_test, Y_test, verbose=0)
print("%s: %.2f%%" % (model.metrics_names[1], scores[1]*100))