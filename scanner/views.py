import json
import re
import whois as whois
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods
from django.shortcuts import render
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from .form import URLForm
import pickle
import sklearn
import math
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
modelfilename = 'finalized_model.sav'
vectorizerfilename = 'finalized_vectorizer.sav'

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

def index(request):
    return render(request, '../templates/index.html')

@require_http_methods(["POST"])
def scan(request):
    #get json sended

    json_data = json.loads(request.body)

    url = json_data['url']
    #escape the url
    baseurl = re.escape(url)

    loaded_model = pickle.load(open(modelfilename, 'rb'))
    loaded_vectorizer = pickle.load(open(vectorizerfilename, 'rb'))
    baseurlwhioutprotocol = baseurl.replace('https://', '')
    baseurlwhioutprotocol = baseurlwhioutprotocol.replace('http://', '')

    # extract robots, entropy, numDigits, urlLength,  hasHttp, hasHttps, bodyLength, scriptLength, ext

    # check if the url has robots.txt, true if it has, false if it doesn't
    try:
        robots = requests.get(f'https://{baseurlwhioutprotocol}/robots.txt')
        robots = 'True' if robots.status_code == 200 else 'False'
    except:
        robots = 'False'

    # calculate the entropy of the url

    prob = [float(baseurl.count(c)) / len(baseurl) for c in dict.fromkeys(list(baseurl))]
    entropy = -sum(p * math.log(p) / math.log(2.0) for p in prob)

    # count the number of digits in the url

    numDigits = sum(c.isdigit() for c in baseurl)

    # count the length of the url

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

    # extract the body of the url for calculating the body length

    try:
        body = requests.get(f'https://{baseurlwhioutprotocol}')
        body = body.text
        bodyLength = len(body)
    except:
        bodyLength = 0
        body = ''

    # extract the script of the url for calculating the script length

    try:
        script = re.findall(r'<script>(.*?)</script>', body)
        scriptLength = len(script)
    except:
        scriptLength = 0

    # extract the extension of the url

    ext = baseurl.split('.')[-1]

    # day since registration of the domain with whois

    try:
        dsr = whois.whois(baseurl)['creation_date']
    except:
        dsr = 0

    # day since expiration of the domain with whois

    try:
        dse = whois.whois(baseurl)['expiration_date']
    except:
        dse = 0

    # concat all the features to one string column

    features = robots + str(entropy) + str(numDigits) + str(urlLength) + hasHttp + hasHttps + str(bodyLength) + str(scriptLength) + ext + str(dsr) + str(dse)
    features = loaded_vectorizer.transform([features]).toarray()

    result = loaded_model.predict(features)

    result_proba = loaded_model.predict_proba(features)

    if result[0] == 'Malicious':
        result_proba = result_proba[0][1]
    else:
        result_proba = result_proba[0][0]

    return JsonResponse({'result': result[0], 'result_proba': result_proba*100 }, safe=False)


