import json
import subprocess
import os
import signal


with open ('closed_world.json') as fp:
    print("Reading closed world websites...")

    cw = json.load(fp)


    for domain in cw['pcaps']:
        subprocess.call("sudo wget -e robots=off --wait 1 -H -p -k %s" %(domain),shell =True)



