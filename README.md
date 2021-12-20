# ai_auto_deploy

An auto deploying, extendable network scanner/AI interpreting app

Sources:
The network-logs and MalwareArtifacts files as well as the AI techniques were derived from 'Hands-On Artificial Intelligence for Cybersecurity' by Alessandro Parisi
GaussianAnomalyDetection is imported from https://github.com/trekhleb/homemade-machine-learning/blob/master/homemade/anomaly_detection/gaussian_anomaly_detection.py, per the above book
Streamlit auto refresh: https://github.com/kmcgrady/streamlit-autorefresh
Both repos above are licensed open source

Pre-requisites:
Docker daemon
Docker-compose ()
Network collection is written for Linux sockets; Windows will be added in future release
Port 8501(http) must be open on host running container

**WARNING**
Network logs are immediately collected and written to disk. Please be mindful of disk usage.
To delete logs, stop running container and run 'docker-compose rm cyberAI'(see below)

Setup and run:

