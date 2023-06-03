import pandas as pd
from sklearn.cluster import KMeans
import numpy as np

def StringToBytes(data):
    sum = 0
    arrbytes = bytes(data, 'utf-8')
    for i in arrbytes:
        sum = sum + i
    return(sum)

features, labels = [], []

meal = open("TestDatasetKmeans.csv", "rt")
for line in meal:
    data_list = line.rsplit(",")
    if(len(data_list) != 13):
        print("error data")
    else:
        data_list.pop(0)
        data_list.pop(0)
        data_list.pop(1)
        data_list[4] = StringToBytes(data_list[4])
        data_list[(len(data_list)-1)]=data_list[(len(data_list)-1)].replace('\n', '')
        features.append(data_list[:(len(data_list)-1)])
        labels.append(data_list[(len(data_list)-1)])
meal.close()

print(features)

#this is your array with the values
X = np.array(features)


#This function creates the classifier
#n_clusters is the number of clusters you want to use to classify your data
kmeans = KMeans(n_clusters=2, random_state=20, init = 'k-means++').fit(X)

#you can see the labels with:
print (kmeans.labels_)

idx = pd.Index(kmeans.labels_)
print(idx.value_counts())

# the output will be something like:
#array([0, 0, 0, 1, 1, 1], dtype=int32)
# the values (0,1) tell you to what cluster does every of your data points correspond to

#You can predict new points with
print(kmeans.predict([features[40]]))

#array([0, 1], dtype=int32)

#or see were the centres of your clusters are
kmeans.cluster_centers_
#array([[ 1.,  2.],
#     [ 4.,  2.]])