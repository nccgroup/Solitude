import argparse
import json
import subprocess
import time
import os
from dotenv import load_dotenv
import sys

from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster

load_dotenv()

def runSolitude(solitudeProcess):
    # This is to prevent connection errors as the it seems like the web app tries to connect to the db before it's been created
    #time.sleep(20)
    # We do this import here because it loads the db on import before the settings from the command line arg can be configured
    from solitude import Solitude
    solitudeAddon = Solitude()

    if os.getenv("DB_HOSTNAME") == 'database':
        opts = options.Options(listen_host='0.0.0.0', listen_port=8080, mode='transparent')
    else:
        opts = options.Options(listen_host='0.0.0.0',listen_port=8080,ignore_hosts=['safebrowsing.googleapis.com'])
    pconf = proxy.config.ProxyConfig(opts)
    m = DumpMaster(opts)
    m.server = proxy.server.ProxyServer(pconf)
    m.addons.add(solitudeAddon)

    try:
        m.run()
    except KeyboardInterrupt:
        solitudeProcess.kill()
        m.shutdown()


def main():
    setEnviroment()
    #time.sleep(20)
    solitudeWebProcess = subprocess.Popen([os.getenv('PYTHON_PATH'), os.getenv('WEBAPP_SCRIPT')], stdout=sys.stdout, stderr=sys.stderr)  # $, env=env)

    runSolitude(solitudeWebProcess)


def setEnviroment():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", default='local',
                        help="local if you want to run locally container if you want to run in a Docker container")
    args = parser.parse_args()


    if args.env == 'container-prod':
        os.environ['ENVIRONMENT'] = 'container-prod'
        os.environ['PYTHON_PATH'] = 'python3'
        os.environ['WEBAPP_SCRIPT'] = '/home/solitude/solitudeWeb.py'

    elif args.env == 'container-dev':
        os.environ['ENVIRONMENT'] = 'container-dev'
        os.environ['PYTHON_PATH'] = '/root/solitude/bin/python3'
        os.environ['WEBAPP_SCRIPT'] = '/mnt/solitudeWeb.py'

    elif args.env == 'local':
        os.environ['ENVIRONMENT'] = 'local'
        os.environ['DB_HOSTNAME'] = '127.0.0.1'
        os.environ['PYTHON_PATH'] = 'python3'
        os.environ['WEBAPP_SCRIPT'] = 'solitudeWeb.py'




if __name__ == '__main__':
    main()
