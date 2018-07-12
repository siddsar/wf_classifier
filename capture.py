import json
import subprocess
import os
import signal
import argparse

parser = argparse.ArgumentParser(description='Covert to json.')
parser.add_argument('--link', default='eth1', help='The connection on which packets are to be captured')
args = parser.parse_args()
link = args.link

with open ('config.json') as fp:
    print("Reading closed world websites...")

    cw = json.load(fp)
    j=0;
    for domain in cw['pcaps']:

        if not os.path.exists("./csv/csv-{}".format(j)):
           os.makedirs("./csv/csv-{}".format(j))

        for i in range(1,41):
            fname = str(i)
            proc = subprocess.Popen(["sudo tshark -i %s -n -T fields -e frame.len -e ip.src -e ip.dst -E separator=, > ./csv/csv-%s/%s.csv &" %(link,str(j),fname)],shell =True)
            subprocess.call("proxychains wget -p %s" %(domain),shell =True)
            proc.terminate()
        j= j+1


