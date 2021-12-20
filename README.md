# ai_auto_deploy

An auto deploying, extendable network scanner/AI interpreting app

**Sources:**<br />
The network-logs and MalwareArtifacts files as well as the AI techniques were derived from 'Hands-On Artificial Intelligence for Cybersecurity' by Alessandro Parisi<br />
GaussianAnomalyDetection is imported from https://github.com/trekhleb/homemade-machine-learning/blob/master/homemade/anomaly_detection/gaussian_anomaly_detection.py, per the above book<br />
Streamlit auto refresh: https://github.com/kmcgrady/streamlit-autorefresh<br />
Both repos above are licensed open source<br />

**Pre-requisites:**<br />
Docker daemon<br />
Docker-compose<br />
Network collection is written for Linux sockets; Windows will be added in future release<br />
Port 8501(http) must be open on host running container<br />

**NOTES**<br />
Please be aware that first time use will build image and app; build process may take up to 5 minutes
Network logs are immediately collected and written to disk. Please be mindful of disk usage.<br />
To delete logs, stop running container and run 'docker-compose rm cyberAI'(see below)

**Setup and run:**<br />
To deploy with docker: 'cd ai_auto_deply; ./start_all.sh'<br />
**Please be aware that first time use will build image and app; build process may take up to 5 minutes**<br />
'cd ai_auto_deploy'<br />
'docker-compose up cyberAI<br />'
Logging will show "You can now view your Streamlit app in your browser."<br />
Open a browser and navigate to http://<your_host_ip>:8501<br />
'docker-compose down cyberAI' to take the service down; logs will be saved and remounted when re-running via 'docker-compose up cyberAI'<br />
'docker-compose rm cyberAI' to remove cached service(container) and logs(container mount points)<br />
