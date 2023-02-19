import math

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import re
import nltk
import sklearn
import whois as whois
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

#add Gradient Boosting Classifier
from sklearn.ensemble import GradientBoostingClassifier

import requests
from sklearn.svm import SVC


def entropy(string):
    "Calculates the Shannon entropy of a string"
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    return -sum(p * math.log(p) / math.log(2.0) for p in prob)

def getTokens(input):
    tokensBySlash = str(input.encode('utf-8')).split('/')
    allTokens=[]
    for i in tokensBySlash:
        tokens = str(i).split('-')
        tokensByDot = []
        for token in tokens:
            tempTokens = str(token).split('.')
            tokentsByDot = tokensByDot + tempTokens
        allTokens = allTokens + tokens + tokensByDot
    allTokens = list(set(allTokens))
    if 'com' in allTokens:
        allTokens.remove('com')
    return allTokens


df = pd.read_csv('scanned_data.csv', error_bad_lines=False, sep=',')
df = pd.DataFrame(df)

#selects sample as much training data that indicates that the URL is good as bad

grouped = df.groupby('vt_class')

counts = grouped.size()

min_count = counts.min()

samples = []
for label, group in grouped:
    sample = group.sample(n=min_count, random_state=42)
    samples.append(sample)

balanced_df = pd.concat(samples)

df = balanced_df



#delete rows with null values

df = df.dropna()



col = ['robots','vt_class', 'entropy', 'numDigits', 'urlLength', 'hasHttp', 'hasHttps', 'bodyLength', 'scriptLength', 'ext', 'dsr', 'dse']
df = df[col]

#vt class is the excepted output, all the other columns are the features

df = df[pd.notnull(df['vt_class'])]
df.columns = ['robots','vt_class', 'entropy', 'numDigits', 'urlLength', 'hasHttp', 'hasHttps', 'bodyLength', 'scriptLength', 'ext', 'dsr', 'dse']
df['category_id'] = df['vt_class'].factorize()[0]
#concat all the features to one string column
df['features'] = df['robots'].map(str) + df['entropy'].map(str) + df['numDigits'].map(str) + df['urlLength'].map(str) + df['hasHttp'].map(str) + df['hasHttps'].map(str) + df['bodyLength'].map(str) + df['scriptLength'].map(str) + df['ext'].map(str) + df['dsr'].map(str) + df['dse'].map(str)


BAD_len = df[df['vt_class'] == 'Malicious'].shape[0]
GOOD_len = df[df['vt_class'] == 'Benign'].shape[0]
plt.bar(10,BAD_len,3, label='BAD URL')
plt.bar(15,GOOD_len,3, label="GOOD URL")
plt.legend()
plt.ylabel('Number of examples')
plt.title('Propoertion of examples')
plt.show()

#crate avec vectorizer

vectorizer = TfidfVectorizer(tokenizer=getTokens)

#vectorize the features
features = vectorizer.fit_transform(df.features).toarray()

#vectorize the labels
labels = df.vt_class



model = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=0).fit(features, labels)
X_train, X_test, y_train, y_test, indices_train, indices_test = train_test_split(features, labels, df.index, test_size=0.20, random_state=0)
model.fit(X_train, y_train)
y_pred_proba = model.predict_proba(X_test)
y_pred = model.predict(X_test)
clf = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=0)
clf.fit(X_train,y_train)
train_score = clf.score(X_train, y_train)
print ('train accuracy =', train_score)



#save the model to disk
import pickle
filename = 'finalized_model.sav'
pickle.dump(model, open(filename, 'wb'))

#save the vectorizer to disk

filename = 'finalized_vectorizer.sav'
pickle.dump(vectorizer, open(filename, 'wb'))

#test the model

baseurl = 'https://www.roketpool.site/'

#delete protocol from the url

baseurlwhioutprotocol = baseurl.replace('https://', '')
baseurlwhioutprotocol = baseurlwhioutprotocol.replace('http://', '')

#extract robots, entropy, numDigits, urlLength,  hasHttp, hasHttps, bodyLength, scriptLength, ext

#check if the url has robots.txt, true if it has, false if it doesn't

try:
    robots = requests.get(f'https://{baseurlwhioutprotocol}/robots.txt')
    robots = 'True' if robots.status_code == 200 else 'False'
except:
    robots = 'False'

#calculate the entropy of the url

entropy = entropy(baseurl)

#count the number of digits in the url

numDigits = sum(c.isdigit() for c in baseurl)

#count the length of the url

urlLength = len(baseurl)

# try check if the url has http with a request, true if it has, false if it doesn't

try:
    hasHttp = requests.get(f'http://{baseurlwhioutprotocol}')
    hasHttp = 'True' if hasHttp.status_code == 200 else 'False'
except:
    hasHttp = 'False'

# try check if the url has https with a request, true if it has, false if it doesn't

try:
    hasHttps = requests.get(f'https://{baseurlwhioutprotocol}')
    hasHttps = 'True' if hasHttps.status_code == 200 else 'False'
except:
    hasHttps = 'False'

#extract the body of the url for calculating the body length

try:
    body = requests.get(f'https://{baseurlwhioutprotocol}')
    body = body.text
    bodyLength = len(body)
except:
    bodyLength = 0
    body = ''

#extract the script of the url for calculating the script length

try:
    script = re.findall(r'<script>(.*?)</script>', body)
    scriptLength = len(script)
except:
    scriptLength = 0

#extract the extension of the url

ext = baseurl.split('.')[-1]

#day since registration of the domain with whois

try:
    dsr = whois.whois(baseurl)['creation_date']
except:
    dsr = 0

#day since expiration of the domain with whois

try:
    dse = whois.whois(baseurl)['expiration_date']
except:
    dse = 0

#concat all the features to one string column

features = robots + str(entropy) + str(numDigits) + str(urlLength) + hasHttp + hasHttps + str(bodyLength) + str(scriptLength) + ext + str(dsr) + str(dse)

#load the model from disk

loaded_model = pickle.load(open('finalized_model.sav', 'rb'))

#load the vectorizer from disk

loaded_vectorizer = pickle.load(open('finalized_vectorizer.sav', 'rb'))

#vectorize the features

features = loaded_vectorizer.transform([features]).toarray()

#predict the class of the url

result = loaded_model.predict(features)

#predict the probability of the url to be malicious

result_proba = loaded_model.predict_proba(features)

print(result)
print(result_proba)



