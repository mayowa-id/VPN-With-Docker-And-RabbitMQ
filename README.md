# VPN-With-Docker-And-RabbitMQ

This project implements a Virtual Private Network (VPN) using Java, Docker, and RabbitMQ for secure communication between nodes. 
The implementation uses TUN interfaces for network traffic handling and provides encrypted communication channels between VPN nodes.

#OVERVIEW 
COMPONENTS 
1. VPN Server
   The following are the functions of the VPN Server class:
   - Creates and manages TUN interfaces
   - Handles packet encryption and deccryption
   - Manages RabbitMQ communication
   - Routes reaffic between nodes
2. RabbitMQ Message Broker
Does the following 
   - Handles inter-node communication
   - Provides reliable message delivery
   - Manages message queues and exchanges
  
4. Docker Container System
   - Isolates VPN nodes
   - Manages networking between containers
   - Provides consistent deployment environment
  
   - NETWORK FLOW
     The following shows the flow of messages through the message broker and the network as a whole
     [Client] → [TUN Interface] → [Encryption] → [RabbitMQ] → [Decryption] → [TUN Interface] → [Destination]

    
        
