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
#include <netdb.h>
#include <arpa/inet.h>

/*/////////////////////////////////////////////////////////////////////////////
//
//  Function: Main
//
//  purpose: entry point of the client code. 
//
*//////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[]) {
    char plaintext[1024]; //assigns memory and values for the plaintext and key that the client wil be sending to encrypt
    char key[1024];
    char good_chars[27] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z',' '}; //intializes the alphabet for later detection of bad characters

    FILE *plaintxt_file;                    //opens up bot the plaintext and key file for reading to copy it's contents and create the message and key from the respected files 
    plaintxt_file = fopen(argv[1], "r");
    fgets(plaintext, sizeof(plaintext), plaintxt_file);
    fclose(plaintxt_file);

    FILE *key_file;
    key_file = fopen(argv[2], "r");
    fgets(key, sizeof(key), key_file);
    fclose(key_file);

    plaintext[strcspn(plaintext, "\n")] = '\0'; //null terminates the plaintext and key files
    key[strcspn(key, "\n")] = '\0';

    //printf("%d\n", strlen(plaintext));
    //printf("%d\n", strlen(key));
    
    if (strlen(key) <= strlen(plaintext)) { //checks if the key is atleast as long as the plaintext
        fprintf(stderr, "Key is not greater than plaintext in length\n");
        return 1;
    }

    int i = 0;  //checks the message for any bad characters by checking if any of the letters in the message are not in the alphabet
    for (i; plaintext[i] != '\0'; i++) {
        if (strchr(good_chars, plaintext[i]) == NULL) {
            fprintf(stderr, "Bad character detected in plaintext file\n");
            return 1;
        }
    }

    // intializes the socket we are connecting to as a TCP IPv6 socket. The socket() command was taught in class. This returns a socket file descriptor telling us which socket we are communicating with
    int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        fprintf(stderr, "Socket error\n");
        return 2;
    }

    //creates a struct for the address information that will store the host we connect to with bind. Basically tells the socket what we should be expecting 
    //this comes from the lecture notes titled "network clients" as is most of the client setup and server setup. This was all taught in class/lecture notes
    struct addrinfo* server_addr_list = NULL;
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    int info_result = getaddrinfo("localhost", argv[3], &hints, //searches the local addresses with the socket we want to connect to (argv[3]) as a string. returns 0 on a success
        &server_addr_list       // this was also taught in class and in the network clients lecture notes. 
        );
    
    if (info_result != 0) { //error checking for addrinfo
        fprintf(stderr, "Error on getaddrinfo\n");
        return 2;
    }
	
    int connect_result = -1;
    struct addrinfo* iter = server_addr_list;
    while (iter != NULL && connect_result == -1) {  //we search through all the possible hosts that have the socket we specified and the localhosts we mentioned in getaddrinfo.
        connect_result = connect(socket_fd, iter->ai_addr, iter->ai_addrlen);   //this method was taught in class as well as in the network clients lecture notes
        iter = iter->ai_next;
    }

    if (connect_result == -1) { //error checking for connect. connect_result returns a 0 on a successful connection to an address and it's socket. 
        fprintf(stderr, "Connect Error\n");
        return 2;
    }

    char message_to_send[2050];
    snprintf(message_to_send, 2050, "%s/%s@@", plaintext, key); //this creates the message we send to the server for encryption. 

    int total_bytes_sent = 0;                       //these are all values intializing the byte arithmatic when we use send. This keeps track
    int bytes_to_send = strlen(message_to_send);    //of how many bytes were sent, how much more we can send, and how many we are sending
    int bytes_remaining = bytes_to_send;
    while (total_bytes_sent < bytes_to_send) {  //loops through, sending each increment of bytes that can fit inside a packet
        int n_bytes_sent = send(socket_fd, message_to_send + total_bytes_sent,  //sends the maximum amount of bytes to the receiving socket. This method was taught in class
        bytes_remaining, 0);                                    //as well as in the network client lecture notes
        if (n_bytes_sent != -1) {
            total_bytes_sent += n_bytes_sent;
            bytes_remaining -= n_bytes_sent;
        }
        else {  //error checks send. On a successful send, send() returns the number of bytes it sent.
            fprintf(stderr, "Send Error\n");
            return 2;
        }
    }

    //now we wait to hear back from the server to receive an encrypted message of whatever we sent over
    char message_received[2049] = {0};
    int total_bytes_received = 0;
    int max_bytes_remaining = 2048;
    while (strstr(message_received, "@@") == NULL) {    //we use "@@" as a way to denote the ending of a message sequence.
        int n_bytes_received = recv(socket_fd,  //we open the socket to see if any information has been sent to us with the recv() command. This tells us
                            message_received + total_bytes_received,    //how many bytes we are receiving on a successful recv() call. It also appends the 
                            max_bytes_remaining, 0);                    // the information to the message_received string. recv() was taught in class and 
        if (n_bytes_received > 0) {                                     // in the network clients and network server notes
            total_bytes_received += n_bytes_received;
            max_bytes_remaining -= n_bytes_received;
        }
        else if (n_bytes_received == 0) {           //error checking for recv(). It returns a 0 if no information was sent, or -1 if recv() fails.
            fprintf(stderr, "Communication terminated\n");
            return 2;
        }
        else {
            fprintf(stderr, "recv() Error\n");
            return 2;
        }

    }
    int len = strlen(message_received); //we then add null terminators and line endings to where the @@ was in the end of the message, and print to standard output as required in the  
    message_received[len - 3] = '\n';   //assignment pdf
    message_received[len - 2] = '\0';
    fprintf(stdout,"%s", message_received);

}
    
