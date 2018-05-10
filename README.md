# SDN-oriented-DDoS-attack-detection-and-mitigation

This repo is for a python based SDN RYU controllers that can detect a DDoS attack on target hosts and mitigate the attack by limiting the bandwidth between the target and the attacker node.

Team Members - 
Mrinali More and Pranati Kulkarni

Instructions:
1. Run custom controller A sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6643 ryu/ryu/app/ControllerA.py | tee log1.txt
2. Run custom controller 2 sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6634 ryu/ryu/app/ControllerB.py | tee log2.txt
3. Run the custom topology sudo python custTopo.py

To launch attacks: 
Victim and protected nodes are A1h1 and A2h2
1. To start intra domain attack:
   B1h1 hping3 --flood --udp A1h1 & 
   B1h1 hping3 --flood --udp AAh2 & 
   B2h1 hping3 --flood --udp A1h1 & 
   B2h1 hping3 --flood --udp A2h2 &
2. To start inter domain attack 
   C1h1 hping3 --flood --udp A1h1 &
   C1h1 hping3 --flood --udp A2h2 & 
   D1h2 hping3 --flood --udp A1h1 & 
   D1h2 hping3 --flood --udp A2h2 &
3. Monitor the controller A and B consoles to see the results and the effective bandwidth on the links.

To mitigate attacks:
1. For intra domain:
DelFlows is defined in code that delete the port of the attacker.
To check perform following command:
B1h1 ping -c 4 A1h1

2. For inter domain: 
ApplyIngress is defined in the code that apply ingress policy as soon as inter domain attack is detected. To check the bandwidth use iperf and following commands:
C1h1 iperf -s &
A1h1 iperf -c C1h1
The bandwidth would be considerably low.



