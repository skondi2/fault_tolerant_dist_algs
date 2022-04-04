# Fault Tolerant Distributed Algorithms
## HW: Asynchronous Reliable Broadcast
- Implemented Bracha's asynchronous broadcast protocol 
  - In asynchronous systems, no broadcast protocol can tolerate a single crash fault
  - We relax the liveness requirements for broadcast
    - Instead of guaranteeing that all nodes will eventually output the same value, we can guarantee that either every node outputs the same value or no node outputs a value.
  - Safety reqirement for broadcast
    - All nodes output the same value
  - Validity requirement for broadcast
    - If the sender node is honest, every node will output the same value 
  - Bracha's Reliable Broadcast Algorithm satisfies the above defined safety, liveness, and validity requirements.  

## HW: Asyncronous Verifiable Secret Sharing 
- Implemented a distributed verifiable secret sharing algorithm with a Secret Sharing and Secret Reconstruction Phase
  - Secret Sharing: 
    - Dealer generates a random secret and uses Bracha's reliable broadcast protocol to share it with all other nodes
  - Reconstruction: 
    - Given each node's share of the secret, each node uses Lagrange interpolation to reconstruct the random secret
    
 Source: https://sites.google.com/view/cs598ftd/home
