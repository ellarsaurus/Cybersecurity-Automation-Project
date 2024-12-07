import smtplib
from email.message import EmailMessage
import psutil
import subprocess
from scapy.all import *
from email.mime.text import MIMEText
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

with open('C:\\Users\\srius\\Downloads\\HDFS_v1\\HDFS.log', 'r') as file:
  logs = file.readlines() #The log file we found online that we are importing

suspicious_logs = [log for log in logs if 'failed' in log.lower() or 'unauthorized' in log.lower()] #Scans for suspicious logs in our file

# with open('summary_report.txt', 'w') as f:
f = open('summary_report.txt', 'w') #opens summary_report.txt
f.write(f"Total suspicious logs found: {len(suspicious_logs)}\n") #Lists the number of suspicious logs found
for log in suspicious_logs: #Lists the suspicious logs
  f.write(log + '\n')
f.close #Closes summary_report.txt


#Get CPU Usage
cpu_usage = psutil.cpu_percent(interval=1) #Uses psutil to find the CPU usage as a percent
print(f"CPU Usage: {cpu_usage}%")

#Get Memory Usage
memory_info = psutil.virtual_memory() #Uses psutil to find Memory usage as a percent
print(f"Memory Usage: {memory_info.percent}%")

with open('performance_log.txt', 'a') as f: #Opens performance_log.txt
  f.write(f"CPU: {cpu_usage}%, Memory: {memory_info.percent}%\n") #Writes CPU and memory usage in performance_log.txt

if cpu_usage > 0.1:
  print("ALERT: High CPU usage detected!") #Outputs alert if CPU usage is > 0.1


def send_alert(subject, body): #defining function to send email
  msg = EmailMessage()
  msg.set_content(body)
  msg['Subject'] = subject
  msg['From'] = 'sriusa.annamalai@gmail.com' #The email the alert is being sent from
  msg['To'] = 'srideviannamalai02@gmail.com' #The email the alert is being sent to

  with smtplib.SMTP_SSL('smtp.sendgrid.net', 465) as smtp:
    smtp.login('apikey', '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') #Using Email API to send alert
    
    try:
      smtp.send_message(msg)
    except Exception as e:
      print(e)

#Example: Send an alert when CPU usage is > 0.1
if cpu_usage > 0.1:
   send_alert('High CPU Usage Alert', f'CPU usage is {cpu_usage}%')


def run_nmap(target): #Defining function: run_nmap
  result = subprocess.run(['nmap', '-sV', target], capture_output=True, text=True) #Uses subprocess to scan for vulnerabilities
  print(result.stdout)

run_nmap('127.0.0.1') #scan local host

def monitor_packets(pkt): #Defining function: monitor_packets
  if pkt.haslayer(TCP) and pkt.haslayer(IP):
    print(f"Source IP: {pkt[IP].src}, Destination IP: {pkt[IP].dst}")

sniff(prn=monitor_packets, count=10) #Capture 10 packets

