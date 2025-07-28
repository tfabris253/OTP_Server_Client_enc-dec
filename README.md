
# Assignment 5 / Final Project: One-Time Pads

	This project utilizes C server/client setups to communicate with one another using one-time pads (OTP) encryption
 	Prominent methods used in this project include:
1. IPv6 addressing and  Sokcet setup
	- addrinfo struct and flags are used to describe the addressing properties of the sockets we open on the network. This allows for IPv6 communication.
2. Host finding
 	- Servers automatically search for local addresses until the server finds a client with the appropriate matching port number, which is gathered at program
	intialization
3. Ability to Handle multiuple clients
   	- Utilizes parrallel handling of multiple connections utilizing C fork() calls. This is handled and cleaned-up as clients finish the encrption or decryption of the text files the clients send to the server. This is done by tracking which new processes are created as clients connect to the server, storing them inside the parent, and checking if any of the processes have finished using the waitpid() call with the WNOHANG flag.
4. OTP encryption
	- Creates a key which is used to encrypt text using the OTP encryption method. In this case, we cypher each letter based on the ASCII values of the key that is randomly generated, and the text that needs to be encrypted. There are important restrictions to this code such as: All text that wants to be encrypted needs to be in upper case, no special characters or numbers are allowed, and the key needs to be atleast as long as the piece of text that is wanted to be encrypted.
 
