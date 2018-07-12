import json
import subprocess
import os
import signal
import argparse

parser = argparse.ArgumentParser(description='Covert to json.')
parser.add_argument('--link', default='eth1', help='The connection on which packets are to be captured')
args = parser.parse_args()
link = args.link

def rmdir_recursive(dir):
    """Remove a directory, and all its contents if it is not already empty."""
    for name in os.listdir(dir):
        full_name = os.path.join(dir, name)
        # on Windows, if we don't have write permission we can't remove
        # the file/directory either, so turn that on
        if not os.access(full_name, os.W_OK):
            os.chmod(full_name, 0600)
        if os.path.isdir(full_name):
            rmdir_recursive(full_name)
        else:
            os.remove(full_name)
    os.rmdir(dir)

with open ('config.json') as fp:
    print("Reading closed world websites...")

    cw = json.load(fp)
    j=0;
    for domain in cw['pcaps']:
        if not os.path.exists("./pcaps/pcap-{}".format(j)):
            os.makedirs("./pcaps/pcaps-{}".format(j))


        if not os.path.exists("./csv/csv-{}".format(j)):
           os.makedirs("./csv/csv-{}".format(j))

        for i in range(1,41):
            fname = str(i)
            proc = subprocess.Popen(["sudo tcpdump -vv -x -X -i %s -A tcp and port not 22 -w ./pcaps/pcaps-%s/%s.pcap &" %(link,str(j),fname)],shell =True)
            subprocess.call("wget -p %s" %(domain),shell =True)
            proc.terminate()
            subprocess.call("tshark -r ./pcaps/pcaps-%s/%s.pcap -T fields -e frame.len -e ip.src -e ip.dst -E separator=, > ./csv/csv-%s/%s.csv" %(str(j),fname,str(j),fname),shell=True)
        rmdir_recursive("pcaps/pcaps-%s"%(str(j)))
        j= j+1

 
