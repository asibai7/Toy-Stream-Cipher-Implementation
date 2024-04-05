#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include </home/asibai7/hw1/Test/libtomcrypt/src/headers/tomcrypt.h>
#include <zmq.h>

// Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
unsigned char* Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Write_File(char fileName[], char input[]);
void Send_via_ZMQ(unsigned char send[], int sendlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <SeedFile>\n", argv[0]);
        return 1; // Exit with an error code.
    }
    //Step 1: Bob receives the ciphertext from Alice via ZeroMQ.
    unsigned char receiveBuffer[1000];
    int receivedLen;
    unsigned char *ciphertext = Receive_via_ZMQ(receiveBuffer, &receivedLen, 1000);
    //Step 2: Bob reads the shared seed from the given filename
    int seedLen;
    unsigned char *seed = Read_File(argv[1], &seedLen); 
    //Step 3: Bob generates the secret key from the shared seed.
    unsigned long prn_length = seedLen;
    unsigned char *secretKey = PRNG(seed, seedLen, prn_length);
    //Step 4: Bob XORs the received ciphertext with the secret key to obtain the plaintext.
    unsigned char* plaintext = (unsigned char*)malloc(seedLen);
    for (int i = 0; i < receivedLen; i++) {
        plaintext[i] = ciphertext[i] ^ secretKey[i];
    }
    printf("Decrypted plaintext: %s\n", plaintext);  
    //Step 5: Bob writes the decrypted plaintext in a file named "Plaintext.txt".
    Write_File("Plaintext.txt", (char*)plaintext);
    printf("Decrypted plaintext written to Plaintext.txt\n");
    //Step 6: Bob hashes the plaintext via SHA256 and Write the Hex format of the hash in a file named "Hash.txt"
    unsigned char* hashResult = Hash_SHA256(plaintext, receivedLen);
    char* hexHash = (char*)malloc(2 * receivedLen);;  
    Convert_to_Hex(hexHash, hashResult, 256/8); 
    Write_File("Hash.txt", hexHash);
    printf("Hex format of the hash written to Hash.txt\n");
    //Step 7: Send the hash over ZeroMQ to Alice as an acknowledgment.
    Send_via_ZMQ(hashResult, 256/8);
    free(ciphertext); 
    free(seed);
    free(secretKey); 
    return 0; 
}
unsigned char* Read_File (char fileName[], int *fileLen) //Function to read from file
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);
    *fileLen = temp_size-1;
	return output;
}
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit) //Function to receive via zmq from Alice
{
	void *context = zmq_ctx_new ();			        	                                 
    void *responder = zmq_socket (context, ZMQ_REP);                                   
   	int rc = zmq_bind (responder, "tcp://*:5555");	                                
    int received_length = zmq_recv (responder, receive, limit, 0);	                  
    unsigned char *temp = (unsigned char*) malloc(received_length);
    for(int i=0; i<received_length; i++){
        temp[i] = receive[i];
    }
    *receivelen = received_length;
    printf("Received Message: %s\n", receive);
    printf("Size is %d\n", received_length-1);
    return temp;
}
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen) //PRNG function
{
	int err;
    unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);
	prng_state prng;                                                                     
    if ((err = chacha20_prng_start(&prng)) != CRYPT_OK){                               
        printf("Start error: %s\n", error_to_string(err));
    }					                
	if ((err = chacha20_prng_add_entropy(seed, seedlen, &prng)) != CRYPT_OK) {          
        printf("Add_entropy error: %s\n", error_to_string(err));
    }	            
    if ((err = chacha20_prng_ready(&prng)) != CRYPT_OK) {                                  
        printf("Ready error: %s\n", error_to_string(err));
    }
    chacha20_prng_read(pseudoRandomNumber, prnlen, &prng);                               
    if ((err = chacha20_prng_done(&prng)) != CRYPT_OK) {                               
        printf("Done error: %s\n", error_to_string(err));
    }
    return (unsigned char*)pseudoRandomNumber;
}
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen) //Hash function
{
    unsigned char *hash_result = (unsigned char*) malloc(inputlen);
    int err;
    hash_state md;                                                         
    sha256_init(&md);                                                    
    sha256_process(&md, (const unsigned char*)input, inputlen);           
    sha256_done(&md, hash_result);                                         
    return hash_result;
}
void Write_File(char fileName[], char input[]) { //Function that writes to file
    FILE *pFile;
    pFile = fopen(fileName, "w");
    if (pFile == NULL) {
        printf("Failed to open the file");
        exit(0);
    }
    fputs(input, pFile);
    fclose(pFile);
}
void Convert_to_Hex(char output[], unsigned char input[], int inputlength) { //Function to convert to Hex
	for (int i=0; i<inputlength; i++){
		sprintf(&output[2*i], "%02x", input[i]);
	}
}
void Send_via_ZMQ(unsigned char send[], int sendlen) { //Function to send via zmq to Alice
    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    printf("Connecting to Alice and sending the acknowledgment...\n");
    zmq_connect(requester, "tcp://localhost:5559");
    zmq_send(requester, send, sendlen, 0);
    zmq_close(requester);
    zmq_ctx_destroy(context);
}
