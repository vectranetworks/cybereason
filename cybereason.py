import json
import argparse
import logging.handlers
import re
import getpass
from datetime import datetime

try:
    import requests
    import pickle
    import vat.vectra as vectra
    from config import cognito_brain, cognito_token, server, port, absolute_path
except ImportError as error:
    print("\nMissing import requirements: %s\n" % str(error))

# Cybereason base URL
base_url = "https://" + server + ":" + port

# Cybereason Request URIs
endpoint_uri = '/rest/visualsearch/query/simple'
sensor_uri = '/rest/sensors/query'
sensor_isolation_uri = '/rest/settings/isolation-rule'
sensor_isolation_delete_uri = sensor_isolation_uri + '/delete'

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
args = parser.parse_args()

# Setup Vectra client
vc = vectra.VectraClient(cognito_brain, token=cognito_token)

# Suppress Detect certificate warning
requests.packages.urllib3.disable_warnings()


def query_cr(url, query_json, method):
    # Returns the response body from the Cybereason query
    # Establish session and import auth cookie
    session = requests.session()

    with open(absolute_path + 'cr_cookie', 'rb') as infile:
        session.cookies.update(pickle.load(infile))

    api_headers = {'Content-Type': 'application/json'}

    query = json.dumps(query_json)

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
        syslog_logger.info('Possible authentication error/stale cookie/un-handled condition')
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

            }
        ]
    }
    results_dict = query_cr(base_url + sensor_uri, ip_query, 'POST')

    return results_dict


def gen_sensor_tags(sensor_dict, hostid):
    # Returns a list of tags from CR context including any previous block/unblock action tags
    # Pull host's tags
    host_tags = vc.get_host_tags(host_id=hostid).json()['tags']

    print('Host tags:{}'.format(host_tags))

    tag_list = [t for t in host_tags if re.search('^Manual\s[un]*block:.*', t)]
    print('tag_list pre CR:{}'.format(tag_list))
    # Define CR attributes interested in
    sensor_attrib = ['machineName', 'siteName', 'department', 'location', 'isolated', 'status',
                     'osType', 'osVersionType']
    if len(sensor_dict):

        if sensor_dict['totalResults'] == 0:
            syslog_logger.debug('Length of sensor_dict = 0')
            tag_list.append('CR_NoAgent')

        elif sensor_dict['totalResults'] == 1:
            syslog_logger.debug('Length of sensor_dict = 1')
            for item in sensor_attrib:
                tag_list.append('{it}: {val}'.format(it=item, val=sensor_dict['sensors'][0][item]))
        else:
            # find most viable sensor candidate
            sensor_list = sensor_dict['sensors']
            syslog_logger.debug('Length of sensor_list:{}'.format(len(sensor_list)))

            index = next((i for i, x in enumerate(sensor_list) if x['status'] == 'Online'), None)
            if index:
                for item in sensor_attrib:
                    tag_list.append('{it}: {val}'.format(it=item, val=sensor_list[index][item]))
            else:
                tag_list.append('CR_MultipleSensors_SameIP_NoActive')

    else:
        tag_list.append('CR_NoAgent')
    print('tag_list:{}'.format(tag_list))
    return tag_list


def query_isolation_by_ip(ip):
    isolation_rule_full_list = query_cr(base_url + sensor_isolation_uri, None, 'GET')
    # Returns list of isolation rules that match IP
    return [r for r in isolation_rule_full_list if r['ipAddressString'] == ip]


def create_isolation_by_ip(ip):
    # Creates an isolation rule based on IP and logs attempt
    isolation = {
        "ipAddressString": ip,
        "port": "443",
        "blocking": "true",
        "direction": "ALL"
    }
    results = query_cr(base_url + sensor_isolation_uri, isolation, 'POST')
    syslog_logger.info('Created isolation rule:{}'.format(results))


def delete_isolation_by_ip(ip):
    # Deletes isolation rule(s) based on IP and logs attempt(s)
    delete_list = query_isolation_by_ip(ip)
    if len(delete_list):
        for rule in delete_list:
            syslog_logger.info('Deleting isolation rule:{}'.format(rule))
            query_cr(base_url + sensor_isolation_delete_uri, rule, 'POST')
    else:
        syslog_logger.info('No isolation rule found to delete for IP:{}'.format(ip))


def poll_vectra(tag=None, tc=None):
    #  Supplied with tag and/or threat/certainty scores, returns dict of host_id:IP
    host_dict = {}
    if tag:
        tagged_hosts = vc.get_hosts(state='active', tags=tag).json()['results']
        for host in tagged_hosts:
            host_dict.update({host['id']: host['last_source']})
    if tc:
        #  t, c = args.tc.split()
        t, c = args.tc[0], args.tc[1]
        tc_hosts = vc.get_hosts(state='active', threat_gte=int(t), certainty_gte=int(c)).json()['results']
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

    login_url = base_url + "/login.html"

    session = requests.session()
    response = session.post(login_url, data=data, verify=True)

    syslog_logger.info('Requesting Cybereason API toke.  Response: {}'.format(response.status_code))

    with open('cr_cookie', 'wb') as outfile:
        pickle.dump(session.cookies, outfile)


def main():

    if args.token:
        gen_token()

    else:
        if args.blocktag:
            hosts = poll_vectra(args.blocktag)
            for hostid in hosts.keys():
                syslog_logger.debug('Requesting isolation rule for IP: {}'.format(hosts[hostid]))
                create_isolation_by_ip(hosts[hostid])
                tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)
                tag_list.append('Manual block:{}'.format(datetime.now().__format__("%Y-%m-%d %H:%M")))
                vc.set_host_tags(host_id=hostid, tags=tag_list, append=False)

        if args.unblocktag:
            hosts = poll_vectra(args.unblocktag)
            for hostid in hosts.keys():
                syslog_logger.debug('Requesting isolation rule deletion for IP: {}'.format(hosts[hostid]))
                delete_isolation_by_ip(hosts[hostid])
                tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)
                tag_list.append('Manual unblock:{}'.format(datetime.now().__format__("%Y-%m-%d %H:%M")))
                vc.set_host_tags(host_id=hostid, tags=tag_list, append=False)

        # Pull hosts with tags and/or threat and certainty scores
        hosts = poll_vectra(args.tag, args.tc)

        for hostid in hosts.keys():
            syslog_logger.info('Pulling enrichment tags for hostid:IP {}:{}'.format(hostid, hosts[hostid]))
            tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)

            vc.set_host_tags(host_id=hostid, tags=tag_list, append=False)

        # sens_dict = query_sensor_by_ip('172.16.1.106')
        # tags = gen_sensor_tags(sens_dict)
        # print(tags)
        # print(query_isolation_by_ip('192.168.36.128'))
        # create_isolation_by_ip('172.16.1.106')
        # delete_isolation_by_ip('172.16.1.106')


if __name__ == '__main__':
    syslog_logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

    #  Update syslog device accordingly for operating system for local logging
    #  handler = logging.handlers.SysLogHandler(address='/dev/log')  # typical for Linux
    handler = logging.handlers.SysLogHandler(address='/var/run/syslog')  # typical for OS X

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    syslog_logger.addHandler(handler)

    main()
