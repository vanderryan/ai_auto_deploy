import socket
import struct
import binascii
import _thread
import threading
import csv
import time
import streamlit as st
import pandas as pd
import numpy as np
import tkinter
import plotly
import plotly.figure_factory as ff
import sys
import module
from sklearn.linear_model import *
from sklearn.tree import *
from sklearn.naive_bayes import *
from sklearn.neighbors import *
from sklearn.metrics import accuracy_score
import matplotlib
import matplotlib.pyplot as plt
from sklearn import ensemble
from sklearn.model_selection import train_test_split
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn import tree
from streamlit_autorefresh import st_autorefresh
from gaussian_anomaly_detection import GaussianAnomalyDetection
import os
from pathlib import Path

def collect_packets():
    #socket for all TCP traffic
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket. htons(0x0800))
    
    while True:
       #capture individual packets
       packet = s.recvfrom(2048)
       
       #Parse ethernet:
       ethernet(packet[0][0:14])
       
       #Parse ip header:
       ip(packet[0][14:34])
      
       #Parse tcp header: 
       tcp(packet[0][34:54])


def tcp(header):
    tcpobj=struct.unpack('!HHLLBBHHH',header)
    data={'Source Port':tcpobj[0], 
    'Destination Port':tcpobj[1], 
    'Sequence Number':tcpobj[2],
    'Acknowledge Number':tcpobj[3],
    'Offset_Reserved':tcpobj[4],
    'Tcp Flag':tcpobj[5],
    'Window':tcpobj[6],
    'CheckSum':tcpobj[7],
    'Urgent Pointer':tcpobj[8]}
    
    tcp_csv = open('tcp_header.csv', 'a')
    tcp_field_names = ['Source Port', 'Destination Port', 'Sequence Number', 'Acknowledge Number', 'Offset_Reserved', 'Tcp Flag', 'Window', 'CheckSum', 'Urgent Pointer']
    tcp_writer = csv.DictWriter(tcp_csv, fieldnames = tcp_field_names)
    
    #check if header exists already
    if 'Port' in open('tcp_header.csv').read():
       tcp_writer.writerow({'Source Port': data.get("Source Port"), 'Destination Port': data.get("Dest. Port"), 'Sequence Number': data.get("Sequence Number"), 'Acknowledge Number': data.get("Acknowledge Number"), 'Offset_Reserved': data.get("Offset_Reserved"), 'Tcp Flag': data.get("Tcp Flag"), 'Window': data.get("Window"), 'CheckSum': data.get("CheckSum"), 'Urgent Pointer': data.get("Urgent Pointer")})
    else:
       tcp_writer.writeheader()
       tcp_writer.writerow({'Source Port': data.get("Source Port"), 'Destination Port': data.get("Destination Port"), 'Sequence Number': data.get("Sequence Number"), 'Acknowledge Number': data.get("Acknowledge Number"), 'Offset_Reserved': data.get("Offset_Reserved"), 'Tcp Flag': data.get("Tcp Flag"), 'Window': data.get("Window"), 'CheckSum': data.get("CheckSum"), 'Urgent Pointer': data.get("Urgent Pointer")})
  
def ethernet(header):
    data={"Source MAC":binascii.hexlify(struct.unpack("!6s6s2s", header)[1]),
          "Destination MAC":binascii.hexlify(struct.unpack("!6s6s2s", header)[0])}
    ethernet_csv =  open('ethernet_header.csv', 'a')
    ethernet_field_names = ['Source MAC', 'Destination MAC']
    ethernet_writer = csv.DictWriter(ethernet_csv, fieldnames = ethernet_field_names)

    #check if header exists already
    if 'MAC' in open('ethernet_header.csv').read():
       ethernet_writer.writerow({'Source MAC': data.get("Source MAC"), 'Destination MAC': data.get("Destination MAC")})
    else:
       ethernet_writer.writeheader()
       ethernet_writer.writerow({'Source MAC': data.get("Source MAC"), 'Destination MAC': data.get("Destination MAC")})

def ip(header):
    ipobj=struct.unpack("!BBHHHBBH4s4s", header)
    data={'Version':ipobj[0],
    "Tos":ipobj[1],
    "Total Length":ipobj[2],
    "Identification":ipobj[3],
    "Fragment":ipobj[4],
    "TTL":ipobj[5],
    "Protocol":ipobj[6],
    "Header CheckSum":ipobj[7],
    "Source Address":socket.inet_ntoa(ipobj[8]),
    "Destination Address":socket.inet_ntoa(ipobj[9])}

    ip_csv =  open('ip_header.csv', 'a')
    ip_field_names = ['Version', 'Tos', 'Total Length', 'Identification', 'Fragment', 'TTL', 'Protocol', 'Header CheckSum', 'Source Address', 'Destination Address']
    ip_writer = csv.DictWriter(ip_csv, fieldnames = ip_field_names)

    #check if header exists already
    if 'TTL' in open('ip_header.csv').read():
       ip_writer.writerow({'Version': data.get("Version"), 'Tos': data.get("Tos"), 'Total Length': data.get("Total Length"), 'Identification': data.get("Identification"), 'Fragment': data.get("Fragment"), 'TTL': data.get("TTL"), 'Protocol': data.get("Protocol"), 'Header CheckSum': data.get("Header CheckSum"), 'Source Address': data.get("Source Address"), 'Destination Address': data.get("Destination Address")})
    else:
       ip_writer.writeheader()
       ip_writer.writerow({'Version': data.get("Version"), 'Tos': data.get("Tos"), 'Total Length': data.get("Total Length"), 'Identification': data.get("Identification"), 'Fragment': data.get("Fragment"), 'TTL': data.get("TTL"), 'Protocol': data.get("Protocol"), 'Header CheckSum': data.get("Header CheckSum"), 'Source Address': data.get("Source Address"), 'Destination Address': data.get("Destination Address")}) 


class collection(threading.Thread):
   def __init__(self):
       threading.Thread.__init__(self)
       self.daemon = True
       self.start()
   def run(self):
       while True:
           collect_packets()

if __name__ == "__main__":

  def streamlit():
     st.title('*AI ----- CYBER ----- DASHBOARD*')
     st.text('______Page refreshes every 15 seconds_____')

     network_analysis()
     malware_assessment()
  
  def malware_assessment():
     ########Malware############
     malware_dataset = pd.read_csv('MalwareArtifacts.csv', delimiter=',')
     st.title('Malware Detection')

     #k means
     km_samples = malware_dataset.iloc[:, [1,2,3,4]].values
     km_targets = malware_dataset.iloc[:, 8].values
     k_means = KMeans(n_clusters=2,max_iter=300)
     k_means.fit(km_samples)
     st.header('K-means labels:')
     st.text(str(k_means.labels_))
     st.header('K-means Clustering Results:')
     st.dataframe(pd.crosstab(km_targets,k_means.labels_,rownames = ["Observed"],colnames = ["Predicted"]))

     #Decision Trees
     dt_samples = malware_dataset.iloc[:, [0, 4]].values
     dt_targets = malware_dataset.iloc[:, 8].values
     dt_training_samples, dt_testing_samples, dt_training_targets, dt_testing_targets = train_test_split(dt_samples, dt_targets, test_size=0.2)
     tree_classifier = tree.DecisionTreeClassifier()
     tree_classifier.fit(dt_training_samples, dt_training_targets)
     dt_predictions = tree_classifier.predict(dt_testing_samples)
     dt_accuracy = 100.0 * accuracy_score(dt_testing_targets, dt_predictions)
     st.header('Decision Tree accuracy:')
     st.text(str(dt_accuracy))

     #Random Forest
     rf_samples = malware_dataset.iloc[:, [0,4]].values
     rf_targets = malware_dataset.iloc[:, 8].values
     rf_training_samples, rf_testing_samples, rf_training_targets, rf_testing_targets = train_test_split(rf_samples, rf_targets, test_size=0.2,)
     rfc =  ensemble.RandomForestClassifier(n_estimators=50)
     rfc.fit(rf_training_samples, rf_training_targets)
     rf_accuracy = rfc.score(rf_testing_samples, rf_testing_targets)
     st.header('Random Forest Classifier accuracy:')
     st.text(str(rf_accuracy))
     
  def network_analysis():
     count = st_autorefresh(interval=15000, limit=None, key=None)
     dataset = pd.read_csv('network-logs.csv')
     data = dataset[['LATENCY', 'THROUGHPUT']].values

     if count >= 0:
       #Traffic From Current Host
       st.title('Traffic From Current Host')      

       ip_dataset = pd.read_csv('ip_header.csv')
       ip_data = ip_dataset[['Source Address', 'Destination Address']].values
       st.text(ip_dataset['Source Address'].value_counts())
       st.text(ip_dataset['Destination Address'].value_counts())

       ethernet_dataset = pd.read_csv('ethernet_header.csv')
       ethernet_data = ethernet_dataset[['Source MAC', 'Destination MAC']]
       st.text(ethernet_data['Source MAC'].value_counts())
       st.text(ethernet_data['Destination MAC'].value_counts())
       
       tcp_dataset = pd.read_csv('tcp_header.csv')
       tcp_data = tcp_dataset[['Source Port', 'Destination Port']]
       #s = tcp_data['Source Port']
       #d = tcp_data['Destination Port']
       #print(tcp_data['Source Port'])
       #print("****************************")
       #print(tcp_data['Destination Port'])
       #if s.empty() or d.empty():
       st.text(tcp_data['Source Port'].value_counts())
       st.text(tcp_data['Destination Port'].value_counts())
          #pass
       #else:
          #st.text(tcp_data['Source Port'].values_counts())
          #st.text(tcp_data['Destination Port'].values_counts())

       #Latency/Throughout Coordinates
       st.title('Network Anomaly Detection')
       plt.scatter(data[:, 0], data[:, 1], alpha=0.6)
       plt.xlabel('LATENCY')
       plt.ylabel('THROUGHPUT')
       plt.title('DATA FLOW')
       st.pyplot(plt)
       
       #MU/sigma squared
       gaussian_anomaly_detection = GaussianAnomalyDetection(data)
       st.header('MU param estimation for network logs:')
       mu_param=gaussian_anomaly_detection.mu_param
       st.text(mu_param)
       st.header('sigma squared estimation for network logs:')
       s_s=gaussian_anomaly_detection.sigma_squared
       st.text(s_s)         

       #Outliers
       targets = dataset['ANOMALY'].values.reshape((data.shape[0], 1))
       probs = gaussian_anomaly_detection.multivariate_gaussian(data)
       (threshold, F1, precision_, recall_, f1_) = gaussian_anomaly_detection.select_threshold(targets, probs)
       outliers = np.where(probs < threshold)[0]
       plt.scatter(data[:, 0], data[:, 1], alpha=0.6, label='Dataset')
       plt.xlabel('LATENCY')
       plt.ylabel('THROUGHPUT')
       plt.title('Network Anomalies')
       plt.scatter(data[outliers, 0], data[outliers, 1], alpha=0.6, c='red', label='Outliers')
       plt.legend()
       st.pyplot(plt)
      
  def collections():
     s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket. htons(0x0800))
     while True:
        #capture individual packets
        packet = s.recvfrom(2048)

        #Parse ethernet:
        ethernet(packet[0][0:14])

        #Parse ip header:
        ip(packet[0][14:34])

        #Parse tcp header:
        tcp(packet[0][34:54])

  def check_for_files():
    if os.path.exists('tcp_header.csv') != True:
      Path('tcp_header.csv').touch()
    if os.path.exists('ip_header.csv') != True:
      Path('ip_header.csv').touch()
    if os.path.exists('ethernet_header.csv') != True:
      Path('ethernet_header.csv').touch()
try:
  check_for_files()
  collect = threading.Thread(target=collections)
  collect.start()
  #Wait for collections to start
  while True:
    if os.path.getsize('tcp_header.csv') == 0:
       pass
    else:
       break
  streamlit()
except KeyboardInterrupt:
   sys.exit()  

