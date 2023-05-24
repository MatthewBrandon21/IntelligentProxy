import pandas as pd
from sklearn.externals import joblib

filename = 'finalized_model.sav'
loaded_model = joblib.load(filename)
dataset = pd.read_csv('Live.csv')
result = loaded_model.predict(dataset[0])
print(result[0])