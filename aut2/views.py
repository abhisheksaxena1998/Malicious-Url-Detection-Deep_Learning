def warn(*args, **kwargs):
    pass
import warnings
warnings.warn = warn
import warnings 
import pandas as pd
import numpy as np
from sklearn.externals import joblib
from lxml import html
from json import dump,loads
from requests import get
import json
import csv
from re import sub
from dateutil import parser as dateparser
from time import sleep
from django.http import HttpResponse
from django.shortcuts import render
import os
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.metrics import classification_report
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix
import pandas as pd 
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
import pickle
from sklearn.externals import joblib 
import whois
import datetime
sns.set_style("darkgrid", {"axes.facecolor": ".3"})
from youtube_transcript_api import YouTubeTranscriptApi

def home(request):
    return render(request,'home.html')

def result(request):
    #nm=request.GET['url']
    try:
        text=request.GET['url']
        if text.startswith('https://') or text.startswith('http://'):

            if len(text)<=9:
                return render(request,'errorpage.html')
            aburl=-1
            digits="0123456789"
            if text[8] in digits:
                oneval=-1
            else:
                oneval=1    
            if len(text)>170:
                secval=-1
            else:
                secval=1  
            if "@" in text:
                thirdval=-1
            else:
                thirdval=1    
            k=text.count("//")          
            if k>1:
                fourthval=-1
            else:
                fourthval=1
                
            if "-" in text:
                fifthval=-1
            else:
                fifthval=1         
            if "https" in text:
                sixthval=1
            else:
                sixthval=-1
            temp=text
            temp=temp[6:]
            k1=temp.count("https")

            if k1 >=1:
                seventhval=-1
            else:
                seventhval=1
            if "about:blank" in text:
                eighthval=-1
            else:
                eighthval=1
            if "mail()" or "mailto:" in text:
                ninthval=-1
            else:
                ninthval=1
            re=text.count("//")          
            if re>3:
                tenthval=-1
            else:
                tenthval=1    

            import whois
            from datetime import datetime

            url=text

            try:
                res=whois.whois(url)
                try:
                    a=res['creation_date'][0]
                    b=datetime.now()
                    c=b-a
                    d=c.days
                except:
                    a=res['creation_date']
                    b=datetime.now()
                    c=b-a
                    d=c.days
                if d>365:
                    eleventhval=1
                else:
                    eleventhval=-1
            except:
                aburl=1
                eleventhval=-1   

            if aburl==1:
                twelthval=-1
            else:
                twelthval=1    




            filename = 'phish_trainedv0.sav'

            loaded_model = joblib.load(filename)

            arg=loaded_model.predict(([[oneval,secval,thirdval,fourthval,fifthval,sixthval,seventhval,eighthval,ninthval,tenthval,eleventhval,twelthval]]))
            print (arg[0])
            if arg[0]==1:
                te="Legitimate"
            else:
                te="Malicious"  
            if arg[0] == 1:
                mal = True
            else:
                mal = False      
            from json.encoder import JSONEncoder
            final_entity = { "predicted_argument": [int(arg[0])]}
            # directly called encode method of JSON
            print (JSONEncoder().encode(final_entity)) 
                
            return render(request,'result.html',{'result':'Real-time analysis successfull','f2':te,'mal': mal,'text':text})
        else:
            return render(request,'errorpage.html')  
    except:
        return render(request,'errorpage.html')          
def about(request):
    return render(request,'about.html')    