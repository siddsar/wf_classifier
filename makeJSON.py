import json
import csv
import argparse

parser = argparse.ArgumentParser(description='Covert to json.')
parser.add_argument('--filename', default='top-1m.csv', help='Name of packet capture file.')
parser.add_argument('--num', default='20', help='IP address of client.')

args = parser.parse_args()

filename = args.filename
num = int(args.num)


dict={}
dict['pcaps']=[]
i = 0
with open(filename,'r') as file:
    for row in file:
        dict['pcaps'].append(row.lstrip('0123456789.,').rstrip('\n'))
        i+=1
        if(i == num):
            break;

with open('config.json', 'w') as outfile:
     json.dump(dict, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False)
