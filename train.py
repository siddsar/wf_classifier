import os
import fingerprint
import json
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn import svm
from sklearn.metrics import accuracy_score
import argparse
import subprocess



parser = argparse.ArgumentParser(description='Process a packet capture.')
parser.add_argument('--thisIP',default='192.168.3.100', help='IP address of this computer.')
parser.add_argument('--ip', default='192.168.3.100', help='IP address of client.')
parser.add_argument('--predict',default='trace.csv', help ="*.pcap file which needs to be processed")
parser.add_argument('--datacount',default = 40 , help="total number of training and test instances for each website")
args = parser.parse_args()


ip_t = args.thisIP
ip = args.ip
filename = args.predict
datacount = args.datacount

print(filename)
print(ip)
print(ip_t)




with open('closed_world.json') as fp:
    cw=json.load(fp)
    j=0
    Data = []
    labels = []
    instance = {}
    websites={}



    trainingcount = 70 * int(datacount) / 100
    datacount = int(datacount)


    for domain in cw['pcaps']:
        for i in range(1,trainingcount):
            instance = fingerprint.make_fingerprint("./csv/csv-%s/%s.csv"%(str(j),str(i)),(ip_t))
            Data.append(instance)
            labels.append(j)
            websites[j] = domain
        j+=1

    j=0
    for domain in cw['pcaps']:
        for i in range(trainingcount,datacount+1):
            instance = fingerprint.make_fingerprint("./csv/csv-%s/%s.csv"%(str(j),str(i)),(ip_t))
            Data.append(instance)
            labels.append(j)
        j+=1


    instance = fingerprint.make_fingerprint("%s"%(filename),(ip))
    Data.append(instance)

    
    v = DictVectorizer(sparse=False)
    data = v.fit_transform(Data)

    X = data
    y = np.array(labels)



    X_train = X[:trainingcount*j-j,:]
    Y_train = y[:trainingcount*j-j]
    print(X)
    print(X_train)
    print(Y_train)
    print(trainingcount)
    classifier = svm.SVC(decision_function_shape = 'ovo',probability=True)
    classifier.fit(X_train,Y_train)


    x_test = X[trainingcount*j-j:,:]
    y_test = y[trainingcount*j-j:]
    print(x_test.shape)
    print(y_test.shape)
    y_predict = classifier.predict(x_test)
    print(y_predict,y_test)
    print("Accuracy: %s%%" % (accuracy_score(y_test, y_predict[:-1]) * 100,))
    
    print("Website detected: %s" %(websites[y_predict[-1]]) )

    probability = classifier.predict_proba(x_test)
    print("confidence %.2f" %(probability[-1,y_predict[-1]]*100))
