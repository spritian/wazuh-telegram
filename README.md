# wazuh-telegram
Python script to send alerts to telegram

1) Ensure permissions are root/execute for the script (or adjust chmod accordingly)
2) If deploying via docker-compose, you will need to modify and add a Dockerfile to include python requests to the wazuh-manager container:

Dockerfile:
FROM wazuh/wazuh-manager:4.3.9
RUN apt update && apt install pip -y && pip install requests

Adjustments to docker-compose.yml (single-node or multi-node) - comment out the image tag and add the build lines below:
    #image: wazuh/wazuh-manager:4.3.9
    build:
      context: .
      dockerfile: Dockerfile
