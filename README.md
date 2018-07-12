# Classifier for Website Fingerprinting Attacks on Tor

For a given closed world of websites, the classifier trains on packet traces of accessing each website and then given a captured packet trace as a csv file. It reports the website detected along with the confidence of the estimate.

## Collecting Data for training.

###Prerequisites

Install tor, proxychains, tshark, numpy,  scipy, scikit-learn.

```

sudo apt-get update
sudo apt-get install tor proxychains tshark
pip install -U numpy
pip install -U scipy
pip install -U scikit-learn

```


### config.json

Add the websites in your closed world in config.json. If you have the list of websites as a csv. Run

```
python makeJSON.py --filename csvfile --num number

```

where csvfile is the name of the csv file, and number is the number of entries in it. This will automatically update config.json.

### Collecting Data for training and testing

Make a empty directory of name csv.

```
mkdir csv

```

Now, run

```
python capture.py --link eth1

```
Replace eth1 by the link on which the data must be captured. if in doubt, try running
```
ifconfig
```
to confirm.


Alternatively, run

```

mkdir csv
mkdir pcaps

python collect.py --link eth1

```

After this step, the csv directory would contain many directories csv-0, csv-1, ... containing packet traces of accesing websites with the corresponding index in config.json.

## Training and predicting

The classifier is an SVM based classifier which trains on the above data. Copy the packet traces to predict as a csv in the current directory. Then  run, 

```
python train.py --thisIP thisip --ip ip --predict filename.csv --datacount number

```

*--thisIP - ip address from which training and test data was collected (presumably this computer)
*--ip - ip address of host in packet traces to predict
*--predict filename (.csv) which contains acket traces to be predicted.
*--datacount total number of training and test instances (it is 40 by default)

## MakeFile

Run the following to start afresh

```
make clean

```


