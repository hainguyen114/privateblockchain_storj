multichain-util create chaindemo 
multichaind chaindemo -daemon 
sleep 5
multichain-cli chaindemo create stream DATA true 
multichain-cli chaindemo create stream PUBKEY true
multichain-cli chaindemo create stream REQUEST true
