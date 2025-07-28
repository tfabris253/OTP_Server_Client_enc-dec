#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/*
//  NAME: Trevor Fabris
//  ASSIGNMENT: OTP enc/decryption between clients and servers
*/

// converts a letter to a number by taking the index of the alphabet array.
char number_to_letter(int num) {
    char Alphabet[27] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',' '};
    return Alphabet[num];
}

int main(int argc, char *argv[]) {
    if (argc < 2) { //basic error checking for keygen script
        fprintf(stderr, "Not enough arguments, exiting code\n");
        return 0;
    }

    //seeds random time for random key generation
	srand(time(NULL));
    int OTPKey_len;
    sscanf(argv[1], "%d", &OTPKey_len); //gets the input from the shell
    
    char OTPkey[OTPKey_len];   //generates key
    int i  = 0;
    for(i; i < OTPKey_len; i++) {
        int rand_int = rand() % 27;
        char rand_char = number_to_letter(rand_int);
        OTPkey[i] = rand_char;

    }
    OTPkey[OTPKey_len + 1] = '\0';  //null terminator at the end for file purposes

    printf("%s\n", OTPkey); //prints the key to standard output.
    return 0;
}
