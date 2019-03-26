In read world, there are many certain ways to harm the Network server database using DDoS attacks. It's always a good practice
for any network admin to identify any uncertainity inside network and take a preventive measures.
The primary goal of this project is as follow
1. Detect the Host inside our network who are trying to download the harmful content from the Black-Listed Website by Company
2. Identify the DDoS attack , find the IP of DDoS influncer and DDoS attacker.
3. Use DDoS attacker IP to find its detailed information using pre-exsited pygeoip python library and Geo.dat

Creation of DDoS attak from local host is illegal and dangerous for any individual. Hence, i created the Local environment
the VMware Fusion where there will be 10 host and 1 Adminstrator of the network. I created the DDoS attack using the ping of deathconcept. Here for learing purpose i defined that if any host gets the packets more then 1000 from outside the network ip, 
it is DDoS attack.

** this project can not perform the live sniffing of the packet because of the hardware limitaion of mine but can plausible.

I will attached all the .pcap file to parse the pcap files by yourself and see the each test case results.
[Test cases can be found into a test_case folder]

You can use Geo.dat file from this repository to extract the info, but it's very old. Thus, you can also use any ip database in the same row, column format.
 
You can pre-defined any Black-list website or any phrase of the website name to find out during pcap parsing.
In this repo, i'm using LOIC phrase[either inside the web search or website name] search or downloaded by the host inside the network, it's low orbit Ion Cannon is used for the creation of the DDoS attack which makes it dangerous for network.
