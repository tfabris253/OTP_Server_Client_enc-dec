#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

// IMPORTANT NOTE: this code was practically copied and pasted from the enc_server. all that was changed has been the decryption process.

//all pid processing functions used here are taken from my own project 3: Smallsh implementation. This is because
//those functions worked well and fulfill the job I need to do in this server. 

/*/////////////////////////////////////////////////////////////////////////////
//
//	function name:  store_pid
//	
//	definition: stores the most recently called child process into an array which keeps track of how many 
// 	child processes need to be terminated once they finish
//
*//////////////////////////////////////////////////////////////////////////////
pid_t* store_pid(pid_t child_pid, pid_t *pid_array, int *size) {
	int new_size = *size + 1;	//increases the size of child pid storage array to make room for new pid
	pid_t* new_array = realloc(pid_array, new_size*sizeof(pid_t));	//reallocates the memory to a new array of pid variables
	new_array[*size] = child_pid;	//places the new pid at the end of the array
	(*size)++;						//increases the integer which keeps track of the size of the array by 1
	return new_array;				//returns the new array with the new child pid
}

/*/////////////////////////////////////////////////////////////////////////////
//
//	function name: remove_pid() 
//	
//	definition: removes the pid of the child which has been reaped
//
*//////////////////////////////////////////////////////////////////////////////
void remove_pid(pid_t *pid_array, int *num_pids, int index_removed) {
	if (*num_pids == 0 || index_removed >= *num_pids) return; //check bounds so no segfaults
	memmove(&pid_array[index_removed], &pid_array[index_removed+1], (*num_pids - index_removed - 1)*sizeof(pid_t));	
	//memmove function to move the memory around in the array to change the array size. This method was found on GeeksForGeeks.com on their
	//C page about the different types of ways you can resize arrays on C
	(*num_pids)--; //decrements size
}

/*/////////////////////////////////////////////////////////////////////////////
//
//	function name: reap_zombie_children
//	
//	definition: iterates through the stored child pid array and looks for any finished processes 
//	and then uses waitpid to call for their information to see if they finished/were signaled to end
//
*//////////////////////////////////////////////////////////////////////////////
void reap_zombie_children(pid_t *pid_array, int *num_pids) {
	int status;
	int i = 0; 
	for(i; i < *num_pids; ) {	//begins iterating through the child pid array
		pid_t result = waitpid(pid_array[i], &status, WNOHANG);	//gets the result from waitpid, with the WNOHANG option to see if the process has ended
																//these function and option was taught in this class
		if (result == pid_array[i]) {	//waitpid returns the pid of the child it is looking at if the process was finsihed/ended
			printf("Child Process: %d has been reaped with ", pid_array[i]);
			if (WIFSIGNALED(status)) {	//checks if the pid being analyzed was eliminated by a signal using WIFSIGNALED which was taught in this class
				printf("signal: %d\n", WTERMSIG(status)); //prints the signal which the process was terminated with, using WTERMSIG, which was taught in this class
			} else if (WIFEXITED(status)) { //checks if the pid being analyzed ended naturally with WIFEXITED function, which was taught in this class
				printf("exit status: %d\n", WEXITSTATUS(status)); //prints the exit status, and gets the exit value with WEXITSTATUS, which was taught in this class
			}
			fflush(stdout);	//flushes stdout
			remove_pid(pid_array, num_pids, i); //removes the most recently analyzed pid from the array
		} else {
			i++;	//goes to next pid if the one we just looked at has not finished
		}
	}
}

/*/////////////////////////////////////////////////////////////////////////////
//
//	function name: tokenize_message
//	
//	definition: tokenizes the message we receive from the client. 
//
*//////////////////////////////////////////////////////////////////////////////
void tokenize_message(char* sent_message, char* plaintext, char* key) {
    char* token = NULL;                         //intializes strtok_r vairablies
    char* message_copy = strdup(sent_message);
    char* save_ptr;
    
    token = strtok_r(message_copy, "/", &save_ptr); //uses the token to create a token of our created message, which seperates the key and plaintext with a /
    strcpy(plaintext, token);   //gets the plaintext
    int len = strlen(plaintext);
    token = strtok_r(NULL, "/", &save_ptr); // gets the key
    strcpy(key, token);
    free(message_copy);
}

/*/////////////////////////////////////////////////////////////////////////////
//
//	function name: decrypt_message
//	
//	definition: decrypts the plaintext according to the OTP standards on wikipedia. Also includes " " characters.
//
*//////////////////////////////////////////////////////////////////////////////
void decrypt_message(char* decrypted_message, char* plaintext, char* key) {
    char Alphabet[27] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z',' '}; // intializes the alphabet for use with decryption
    int alphabet_index;
    int key_index;
    int i = 0;
    for (i; plaintext[i] != '\0'; i++) {    //iterates through each character inside the plaintext.
                
        if (plaintext[i] != ' ') { //if that character is not a space, we assign it by subtracting it by 'A' which returns it's index of the the alphabet. This is due to ASCII aritmetic
            alphabet_index = plaintext[i] - 'A';
        } else {
            alphabet_index = 26;    // if it is a space, we assign it to the last index in the alphabet, the " " index
        }
        if (key[i] != ' ') {           // same idea as above but for the key
            key_index = key[i] - 'A';
        } else {
            key_index = 26;
        }
        int plain_index = (alphabet_index - key_index + 27);  //uses modulo logic to "wrap" the alphabet to obtain an encrypted key, as suggested in the assignment pdf. 
        plain_index = plain_index % 27;
        decrypted_message[i] = Alphabet[plain_index];
    }
    decrypted_message[i] = '@'; //adds the @@ to denote the ending of the decryted message.
    decrypted_message[i + 1] = '@';
    decrypted_message[i + 2] = '\n';
    decrypted_message[i + 3] = '\0';
}

/*/////////////////////////////////////////////////////////////////////////////
//
//	function name: main
//	
//	definition: entry point to the dec_server code
//
*//////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {
    int num_pids = 0;   //intiallize the pid_array to track all of the concurrent porocesses the server is running, as asked for in the assignment script
    pid_t *pid_array = NULL;
    
    int port_num;   // same idea as in the client. creates a socket file descriptor which we will be able to listen for connections on. 
    int listen_socket_fd = socket(AF_INET6, SOCK_STREAM, 0); // TCP socket with IPv6 addresses. 
    if (listen_socket_fd == -1) {
        fprintf(stderr, "Socket Error\n");
        return 1;
    }
    sscanf(argv[1], "%d", &port_num);   //creates the port number from shell input
    
    struct sockaddr_in6 bind_addr;   // describes IPv6 socket addresses which clients can bind to
    bind_addr.sin6_family = AF_INET6; // describes that we are using IPv6 addressing
    bind_addr.sin6_port = htons(port_num);//creates the port number
    bind_addr.sin6_addr = in6addr_any;  //listens to all inputs on current machine. For IPv6, I followed the linux man pages as well as github page by inaz2 which demonstrates a setup method
                                        // for IPv6 (here is the link: https://gist.github.com/inaz2/0e77c276a834ad8e3131). Linux man for Ipv6 and sockaddr_in6 was helpful as well. 

    int bind_result = bind( // same idea as in client, we bind our socket to the bind address we created above with our socket information. This was shown in the network servers lecture notes. 
        listen_socket_fd, (struct sockaddr*) &bind_addr,    
        sizeof(bind_addr)
        );
    if (bind_result == -1) {
        fprintf(stderr, "Bind Error\n");
        return 1;
    }

    int listen_result = listen(listen_socket_fd, 5);    //we begin listening on the socket we just created. it can hold up to 5 concurrent conenctions. this will conenct us
    if (listen_result == -1) {                          // to a client. listen was taught in the network server lecture notes.
        fprintf(stderr, "Listen Error\n");
        return 1;
    }
    
    // we begin handling all the connections with fork here. 
    int dont_fork_bomb = 0; // I used this to not fork bomb the OS1 servers by accident. 
    while(dont_fork_bomb < 5) {
        reap_zombie_children(pid_array, &num_pids); // reaps children processes when they are finished. 

        struct sockaddr_in client_addr; //creates an address of the client from the socket that wants to connect to us. This is done through accept(). accept was taught in the network server
        socklen_t client_addr_size = sizeof(client_addr);   // lecture notes. 
        int communication_socket_fd = accept(listen_socket_fd, // creates a file descriptor of the socket that is connecting to us. 
            (struct sockaddr*) &client_addr, &client_addr_size
            );
        if (communication_socket_fd == -1) {    //if it does not return a socket fd, it returns -1 and fails.
            fprintf(stderr, "Accept Error\n");
            continue;
        }
        else {  //now that we are connected to the socket, we fork and begin handling things in the background. 
            pid_t new_pid = fork();
            if (new_pid == 0) {
                // in child
                char message_received[2048] = {0};  //same ideas as in the lient. We receive the plaintext from the enc_client, decrypt it, and send it back. 
                int total_bytes_received = 0;
                int max_bytes_remaining = 2048;
                while(strstr(message_received, "@@") == NULL) { //using recv(), we get the plaintext frmo the enc_client, and store it's information. 
                    int n_bytes_received = recv(communication_socket_fd,    // recv() was taught in the network client & network server lecture notes. 
                    message_received + total_bytes_received, 
                    max_bytes_remaining, 0
                );
                if (n_bytes_received > 0) {
                    total_bytes_received += n_bytes_received;
                    max_bytes_remaining -= n_bytes_received;
                }
                else if (n_bytes_received == 0) {           //recv() error handling. same thing as in enc_client
                    printf("Sender terminated message communication\n");
                    return 1;
                }
                else {
                    printf("Error on recv()\n");
                    return 1;
                }

                }

                //we now strip the end of message @@ with null terminators. 
                size_t len = strlen(message_received);
                message_received[len - 1] = '\0';
                message_received[len - 2] = '\0';
                //printf("Message from client: %s\n", message_received);

                //intialize values for plaintext and key respectively
                char plaintext[1024];
                char key[1024];

                //tokenizes the received message
                tokenize_message(message_received, plaintext, key);

                //printf("%s\n", plaintext);
                //printf("%s\n", key);

                // decryprts the received message
                char decrypted_message[1024];
                decrypt_message(decrypted_message, plaintext, key);

                //sends the decrypted message back to enc_client. This is the same process as when the client sends the plaintext. 
                // send() is used and was taught in the network server and network client lecture notes as well as in class. 
                
                //intializes values to keep track of what has been sent so far. 
                int total_bytes_sent = 0;
                int bytes_to_send = strlen(decrypted_message);
                int bytes_remaining = bytes_to_send;
                while (total_bytes_sent < bytes_to_send) {
                    int n_bytes_sent = send(communication_socket_fd,        //sends the information using send
                                    decrypted_message + total_bytes_sent,
                                    bytes_remaining, 0
                                    );  
                    if (n_bytes_sent != -1) {               //error checks send
                        total_bytes_sent += n_bytes_sent;
                        bytes_remaining -= n_bytes_sent;
                    } 
                    else {
                        fprintf(stderr, "Send Error\n");
                    }
                }
                
            }
            else {
                // in parent
                //printf("Backgound process started, process ID: %d\n", new_pid); //lets user know that a backgroun d process was created
				//fflush(stdout);	//flushes stdout 

				//saves PID of child
				pid_array = store_pid(new_pid, pid_array, &num_pids);
            }

        }

        dont_fork_bomb++;
    }

}
