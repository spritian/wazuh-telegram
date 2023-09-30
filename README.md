# wazuh-telegram
Python script to send Wazuh alerts to Telegram

1) Ensure permissions are root/execute for the script (or adjust chmod accordingly)
2) If deploying Wazuh via docker-compose, you will need to modify and add a Dockerfile to include python requests to the wazuh-manager container - skip to step 5, if not:

3) Create a new 'Dockerfile':

Dockerfile

    FROM wazuh/wazuh-manager:4.3.9
    RUN apt update && apt install pip -y && pip install requests

4) Adjustments to docker-compose.yml (single-node or multi-node) - comment out the image tag and add the build lines below - you'll also need to mount the script in the volumes line further down:

docker-compose.yml

    services:
      wazuh.manager:
        #image: wazuh/wazuh-manager:4.3.9
        build:
          context: .
          dockerfile: Dockerfile

    ...

    volumes:
    - ./config/custom-telegram.py:/var/ossec/integrations/custom-telegram

5) Modify 'wazuh_manager.conf' (located in single-node/config/wazuh_cluster or multi-node/config/wazuh_cluster) and insert the following block (be sure to replace <YOURBOTID> with your bot ID):

wazuh_manager.conf

    <ossec_config>
      <global>
        <integration>
          <name>custom-telegram</name>
          <hook_url>https://api.telegram.org/bot<YOURBOTID>/sendMessage</hook_url>
          <alert_format>json</alert_format>
        </integration>
      ...

Note: Log level in my ossec.conf is 3 - I filtered out CIS/SCA and other items as defined in the script. Custom overrides (formatting) for specific Sharepoint and Office365 alerts are also coded in the script.
