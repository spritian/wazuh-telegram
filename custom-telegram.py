#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip3 install requests")
    sys.exit(1)

# Define discards

# 86003: Docker: Error message
# 5104 : Interface entered promiscuous(sniffing) mode
# 533  : Listened ports status changed
# 5134 : RNGD failure
# 550  : Integrity checksum changed
# 591  : Log file rotated
# 510  : Host-based anomaly detection event (rootcheck)
DENY_RULE_ID = ["86003", "5104", "533", "5134", "550", "591", "510"]
DENY_LOCATION = ["sca"]
CHAT_ID = "XXXXXXX"

def create_message(alert_json):
    setformat = "0"

    # Get alert information
    title = alert_json['rule']['description'] if 'description' in alert_json['rule'] else ''
    description = alert_json['full_log'] if 'full_log' in alert_json else ''
    description.replace("\\n", "\n")
    alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else ''
    groups = ', '.join(alert_json['rule']['groups']) if 'groups' in alert_json['rule'] else ''
    rule_id = alert_json['rule']['id'] if 'rule' in alert_json else ''
    agent_name = alert_json['agent']['name'] if 'name' in alert_json['agent'] else ''
    agent_id = alert_json['agent']['id'] if 'id' in alert_json['agent'] else ''

    # Additional context for 'Office 365: Secure Token Service (STS) logon events in Azure Active Directory.'
    if rule_id == "91545":
        data_o365_rs = alert_json['data']['office365']['ResultStatus'] if 'ResultStatus' in alert_json['data']['office365'] else ''
        data_o365_userid = alert_json['data']['office365']['UserId'] if 'UserId' in alert_json['data']['office365'] else ''
        data_o365_ip = alert_json['data']['office365']['ClientIP'] if 'ClientIP' in alert_json['data']['office365'] else ''
        title = f'*Office 365:* User Login {data_o365_rs}\n*User:* {data_o365_userid}\n*IP:* {data_o365_ip}\n\n{title}'
        setformat = "1"

    # Additional context for 'Office 365: Phishing and malware events from Exchange Online Protection and Microsoft Defender for Office 365.'
    if rule_id == "91556":
        data_o365_da = alert_json['data']['office365']['DeliveryAction'] if 'DeliveryAction' in alert_json['data']['office365'] else ''
        data_o365_direction = alert_json['data']['office365']['Directionality'] if 'Directionality' in alert_json['data']['office365'] else ''
        data_o365_ldl = alert_json['data']['office365']['LatestDeliveryLocation'] if 'LatestDeliveryLocation' in alert_json['data']['office365'] else ''
        data_o365_to = alert_json['data']['office365']['Recipients'] if 'Recipients' in alert_json['data']['office365'] else ''
        data_o365_to.replace('\'', '')
        data_o365_from = alert_json['data']['office365']['P2Sender'] if 'P2Sender' in alert_json['data']['office365'] else ''
        data_o365_subject = alert_json['data']['office365']['Subject'] if 'Subject' in alert_json['data']['office365'] else ''        
        title = f'*Office 365:* {data_o365_da} Mail {data_o365_direction} ({data_o365_ldl})\n\n*To:* {data_o365_to}\n*From:* {data_o365_from}\n*Subject:* {data_o365_subject}\n*![Review](https://security.microsoft.com/quarantine?viewid=Email)*\n\n{title}'
        setformat = "1"

    # Additional context for 'Office 365: SharePoint file operation events.'
    if rule_id == "91537":
        data_o365_platform = alert_json['data']['office365']['Platform'] if 'Platform' in alert_json['data']['office365'] else ''
        data_o365_op = alert_json['data']['office365']['Operation'] if 'Operation' in alert_json['data']['office365'] else ''
        data_o365_sr = alert_json['data']['office365']['SourceRelativeUrl']+"/" if 'SourceRelativeUrl' in alert_json['data']['office365'] else ''
        data_o365_fn = alert_json['data']['office365']['SourceFileName'] if 'SourceFileName' in alert_json['data']['office365'] else ''
        data_o365_userid = alert_json['data']['office365']['UserId'] if 'UserId' in alert_json['data']['office365'] else ''
        data_o365_ip = alert_json['data']['office365']['ClientIP'] if 'ClientIP' in alert_json['data']['office365'] else ''
        data_o365_wl = alert_json['data']['office365']['Workload'] if 'Workload' in alert_json['data']['office365'] else ''
        title = f'*SharePoint:* {data_o365_wl} ({data_o365_platform})\n\n*{data_o365_op}:*\n- {data_o365_sr}{data_o365_fn}\n\n*User:* {data_o365_userid}\n*IP:* {data_o365_ip}\n\n*{title}*'
        setformat = "1"
        
    # Format message with markdown
    if setformat == "1":
        msg_content = f'{title}\n\n'
    else:
        msg_content = f'*{title}*\n\n'

    msg_content += f'_{description}_\n'
    msg_content += f'*Groups:* {groups}\n' if len(groups) > 0 else ''
    msg_content += f'*Rule:* {rule_id} (Level {alert_level})\n'
    msg_content += f'*Agent:* {agent_name} ({agent_id})\n' if len(agent_name) > 0 else ''

    msg_data = {}
    msg_data['chat_id'] = CHAT_ID
    msg_data['text'] = msg_content
    msg_data['parse_mode'] = 'markdown'

    # Debug information
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f'MSG: {msg_data}\n')

    return json.dumps(msg_data)

# Read configuration parameters
alert_file = open(sys.argv[1])
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Send the request
msg_data = create_message(alert_json)
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

if alert_json['location'] not in DENY_LOCATION and alert_json['rule']['id'] not in DENY_RULE_ID and "IGNORE" not in alert_json['rule']['description']:
    response = requests.post(hook_url, headers=headers, data=msg_data)
    
    # Debug information - move after if statement if you want to log discards for debugging
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f'RESPONSE: {response}\n\n')
else:
    response = "\n*** DISCARDED ***\n     - DENY_RULE_ID: " + alert_json['rule']['id'] + "\n     - DENY_LOCATION: " + alert_json['location'] + "\n     - IGNORE: " + alert_json['rule']['description']

sys.exit(0)
