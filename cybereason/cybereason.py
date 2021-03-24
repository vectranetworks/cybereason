__title__ = 'Cybereason scripted integration'
__version__ = '1.0'
__copyright__ = 'Vectra AI, Inc.'
__status__ = 'Production'

import json
import argparse
import logging.handlers
import re
import getpass
from datetime import datetime
import pickle
import os
import sys

try:
    import requests
    import validators
    import vat.vectra as vectra
    from .config import COGNITO_BRAIN, COGNITO_TOKEN, SERVER, PORT
except Exception as error:
    print("\nMissing import requirements: %s\n" % str(error))

# Cybereason base URL
BASE_URL = "https://" + SERVER + ":" + PORT

# Cybereason Request URIs
ENDPOINT_URI = '/rest/visualsearch/query/simple'
SENSOR_URI = '/rest/sensors/query'
SENSOR_ISOLATION_URI = '/rest/monitor/global/commands/isolate'
SENSOR_ISOLATION_DELETE_URI  = '/rest/monitor/global/commands/un-isolate'

# Setup Vectra client
VC = vectra.VectraClient(COGNITO_BRAIN, token=COGNITO_TOKEN)

# Suppress Detect certificate warning
requests.packages.urllib3.disable_warnings()

# Setup logging
LOG = logging.getLogger(__name__)


def validate_config(func):
    def config_validator():
        if bool(validators.url(COGNITO_BRAIN) and validators.url(BASE_URL)):
            return func()
        else:
            raise Exception('Ensure config.py has valid Cybereason and Vectra config sections located in the following '
                            'directory:\n{}'.format(os.path.dirname(__file__)))

    return config_validator


def query_cr(url, query_json, method):
    # Returns the response body from the Cybereason query
    # Establish session and import auth cookie
    session = requests.session()

    with open(os.path.dirname(__file__) + 'cr_cookie', 'rb') as infile:
        session.cookies.update(pickle.load(infile))

    api_headers = {'Content-Type': 'application/json'}

    query = json.dumps(query_json)

    LOG.debug(query)

    api_response = session.request(method, url, data=query, headers=api_headers)

    if api_response.status_code == 200 and not (re.search('<title>Cybereason \| Login</title>', api_response.text)):
        # Handle isolation rule deletion not returning any content
        if len(api_response.content) > 0:
            valid_response = json.loads(api_response.content)

            return valid_response
        else:
            return None

    elif api_response.status_code == 400 and re.search('NO_MATCHING_SENSORS', api_response.text):

        return None

    else:
        LOG.info('Possible authentication error/stale cookie/un-handled condition')
        exit()


def query_sensor_by_ip(ip):
    # Returns a dictionary of sensors
    ip_query = {
        "limit": 500,
        "offset": 0,
        "filters": [
            {
                "fieldName": "internalIpAddress",
                "operator": "Equals",
                "values": [ip]
            },
	        {
		        "fieldName": "status",
                "operator": "NotEquals",
                "values": ["Archived","Stale"]
            }
        ]
    }
    results_dict = query_cr(BASE_URL + SENSOR_URI, ip_query, 'POST')

    return results_dict


def query_online_sensor_by_ip(ip):
    """ 
    Query for sensors per IP with online status.
    :param ip: ip address of the target machine
    :return: return a dictionary with the matching sensors
    """

    ip_query = {
        "limit": 500,
        "offset": 0,
        "filters": [
            {
                "fieldName": "internalIpAddress",
                "operator": "Equals",
                "values": [ip]

            },
            {
                "fieldName": "status",
                "operator": "Equals",
                "values": ["Online"]
            }
        ]
    }
    results_dict = query_cr(BASE_URL + SENSOR_URI, ip_query, 'POST')

    return results_dict


def gen_sensor_tags(sensor_dict, hostid):
    # Returns a list of tags from CR context including any previous block/unblock action tags
    # Pull host's tags
    host_tags = VC.get_host_tags(host_id=hostid).json()['tags']

    LOG.debug('Host tags:{}'.format(host_tags))

    tag_list = [t for t in host_tags if re.search('^Manual\s[un]*block:.*', t)]
    LOG.debug('tag_list pre CR:{}'.format(tag_list))
    # Define CR attributes interested in
    sensor_attrib = ['machineName', 'siteName', 'department', 'location', 'isolated', 'status',
                     'osType', 'osVersionType']
    if len(sensor_dict):

        if sensor_dict['totalResults'] == 0:
            LOG.debug('Length of sensor_dict = 0')
            tag_list.append('CR_NoAgent')

        elif sensor_dict['totalResults'] == 1:
            LOG.debug('Length of sensor_dict = 1')
            for item in sensor_attrib:
                tag_list.append('{it}: {val}'.format(it=item, val=sensor_dict['sensors'][0][item]))
        else:
            # find most viable sensor candidate
            sensor_list = sensor_dict['sensors']
            LOG.debug('Length of sensor_list:{}'.format(len(sensor_list)))

            index = next((i for i, x in enumerate(sensor_list) if x['status'] == 'Online'), None)
            if index:
                for item in sensor_attrib:
                    tag_list.append('{it}: {val}'.format(it=item, val=sensor_list[index][item]))
            else:
                tag_list.append('CR_MultipleSensors_SameIP_NoActive')

    else:
        tag_list.append('CR_NoAgent')
    
    return tag_list


def query_isolation_by_ip(ip):
    isolation_rule_full_list = query_cr(BASE_URL + SENSOR_ISOLATION_URI, None, 'GET')
    # Returns list of isolation rules that match IP
    return [r for r in isolation_rule_full_list if r['ipAddressString'] == ip]


def create_isolation_by_pylumid(pylumid):
    """
    Isolate a host based on its sensor pylum ID
    param plyumid: The sensor pylum ID
    """

    isolation  = { 
        "pylumIds":[pylumid],
        "malopId": "" 
    }
    
    results = query_cr(BASE_URL + SENSOR_ISOLATION_URI, isolation, 'POST')
    LOG.info(f"Isolate host: {results}")

def delete_isolation_by_pylumid(pylumid):
    """
    Delete an isolation rule based on the sensor pylum ID.
    :param plyumid: The sensor pylum ID
    """
    isolation  = { 
        "pylumIds":[pylumid],
        "malopId": "" 
    }
    
    results = query_cr(BASE_URL + SENSOR_ISOLATION_DELETE_URI, isolation, 'POST')
    LOG.info(f"Un-isolate host: {results}")


def poll_vectra(tag=None, tc=None):
    #  Supplied with tag and/or threat/certainty scores, returns dict of host_id:IP
    host_dict = {}
    if tag:
        tagged_hosts = VC.get_hosts(state='active', tags=tag).json()['results']
        for host in tagged_hosts:
            host_dict.update({host['id']: host['last_source']})
    if tc:
        #  t, c = args.tc.split()
        t, c = tc[0], tc[1]
        tc_hosts = VC.get_hosts(state='active', threat_gte=int(t), certainty_gte=int(c)).json()['results']
        for host in tc_hosts:
            host_dict.update({host['id']: host['last_source']})
    return host_dict


def gen_token():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    uname = input("Cybereason username: ")
    passw = getpass.getpass()

    data = {
        "username": uname,
        "password": passw
    }


    login_url = BASE_URL + "/login.html"

    session = requests.session()
    response = session.post(login_url, headers=headers, data=data, verify=True)

    LOG.info('Requesting Cybereason API token.  Response: {}'.format(response.status_code))

    with open(os.path.dirname(__file__) + 'cr_cookie', 'wb') as outfile:
        pickle.dump(session.cookies, outfile)


    return session




def obtain_args():
    parser = argparse.ArgumentParser(description='Poll Cognito for tagged hosts, extracts Cybereason contextual '
                                                 'information.  Block or unblock hosts per tags',
                                     prefix_chars='--', formatter_class=argparse.RawTextHelpFormatter,
                                     epilog='')
    parser.add_argument('--token', action='store_true', help='Generate Cybereason API token.  Prompts for credentials.')
    parser.add_argument('--tc', type=int, nargs=2, default=False,
                        help='Poll for hosts with threat and certainty scores >=, eg --tc 50 50')
    parser.add_argument('--tag', type=str, nargs=1, default=False, help='Enrichment host tag to search for')
    parser.add_argument('--blocktag', type=str, nargs=1, default=False, help='Block hosts with this tag')
    parser.add_argument('--unblocktag', type=str, nargs=1, default=False, help='Unblock hosts with this tag')
    parser.add_argument('--verbose', default=False, action='store_true', help='Verbose logging')

    return parser.parse_args()


@validate_config
def main():

    args = obtain_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) == 1:
        print('Run cybereason -h for help.')
        sys.exit()

    if args.token:
        gen_token()

    else:
        if args.blocktag:
            hosts = poll_vectra(args.blocktag)
            for hostid in hosts.keys():
                LOG.debug(hosts[hostid])
                LOG.debug('Requesting isolation rule for IP: {}'.format(hosts[hostid]))
                sensor_list = query_online_sensor_by_ip(hosts[hostid])['sensors']
                LOG.debug(sensor_list)
                LOG.debug('Number of Sensors: {}'.format(len(sensor_list)))
                for sensor in sensor_list:
                    LOG.info(f"[ISOLATE] Hostnane: {sensor['machineName']} - Sensor pylum ID : "+sensor['pylumId'])
                    create_isolation_by_pylumid(sensor['pylumId'])
                    tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)
                    tag_list.append('Manual block:{}'.format(datetime.now().__format__("%Y-%m-%d %H:%M")))
                    VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)

        if args.unblocktag:
            hosts = poll_vectra(args.unblocktag)
            for hostid in hosts.keys():
                LOG.debug('Requesting isolation rule deletion for IP: {}'.format(hosts[hostid]))
                sensor_list = query_online_sensor_by_ip(hosts[hostid])['sensors']
                LOG.debug(sensor_list)
                LOG.debug('Number of Sensors: {}'.format(len(sensor_list)))
                for sensor in sensor_list:
                    LOG.info(f"[UN-ISOLATE] Hostnane: {sensor['machineName']} - Sensor pylum ID : "+sensor['pylumId'])
                    delete_isolation_by_pylumid(sensor['pylumId'])
                    tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)
                    tag_list.append('Manual unblock:{}'.format(datetime.now().__format__("%Y-%m-%d %H:%M")))
                    VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)

        # Pull hosts with tags and/or threat and certainty scores
        hosts = poll_vectra(args.tag, args.tc)

        for hostid in hosts.keys():
            LOG.info('Pulling enrichment tags for hostid:IP {}:{}'.format(hostid, hosts[hostid]))
            tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)

            VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)


if __name__ == '__main__':

    main()
