import requests

field = "nama"
count = 5

url = 'https://randomizer-api.vercel.app/api/random'
myobj = {'field': field, 'count' : count}

x = requests.post(url, json = myobj)

#print the response text (the content of the requested file):

print(x.text)
