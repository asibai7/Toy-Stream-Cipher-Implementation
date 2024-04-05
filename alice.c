//Ahmad Sibai, HW1 Crypto
#include <stdlib.h>
#include <stdio.h>
#include </home/asibai7/hw1/Test/libtomcrypt/src/headers/tomcrypt.h>
#include <string.h>
#include <zmq.h>
#define MIN_SIZE 32

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Send_via_ZMQ(unsigned char send[], int sendlen);
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Write_File(char fileName[], char input[]);
unsigned char* Read_File(char fileName[], int *fileLen);

int main(int argc, char *argv[]) {
    FILE *file;
    unsigned char *secretKey;
    int bytesRead;
    //Step 1: Read the message from Message.txt
    int messageLen = 0;
    unsigned char *message = Read_File(argv[1], &messageLen);
    unsigned char ciphertext[messageLen];
    if(messageLen < 32) {
    	printf("Error: Message size must be at least 32 bytes.\n");
    	exit(1);
    }
    //Step 2: Read the shared seed from SharedSeed.txt
    int seedLen;
    unsigned char *seed = Read_File(argv[2], &seedLen);
    //Step 3: Generate the secret key
    secretKey = PRNG(seed, seedLen, messageLen);
    //Step 4: Write the hex-formatted secret key to "Key.txt"
    char hexKey[2*messageLen];
    Convert_to_Hex(hexKey, secretKey, messageLen);
    FILE* keyFile = fopen("Key.txt", "w");
    fprintf(keyFile, "%s", hexKey);
    fclose(keyFile);
    //Step 5: XOR the message with the secret key to obtain the ciphertext
    for (int i = 0; i < messageLen; i++) {
        ciphertext[i] = message[i] ^ secretKey[i];
    }
    //Step 6: Write the ciphertext to "Ciphertext.txt"
    char cipherTextStr[messageLen * 2 + 1];  // +1 for the null terminator
    Convert_to_Hex((unsigned char *)cipherTextStr, ciphertext, messageLen);
    Write_File("Ciphertext.txt", (unsigned char *)cipherTextStr);
    // 7: Send the ciphertext to Bob via ZeroMQ
    Send_via_ZMQ(ciphertext, seedLen);
    unsigned char* localHash = Hash_SHA256(message, messageLen);
    //Step 8: Wait for acknowledgment from Bob using the provided Receive_via_ZMQ
    int receivedLen;
    int limit = 1000;
    unsigned char receivedHash[limit]; // SHA-256 outputs 256 bits or 32 bytes
    unsigned char *received_message = Receive_via_ZMQ(receivedHash, &receivedLen, limit);
    //Step 9: Compare local with receive to approve acknowledgement
    if (memcmp(localHash, receivedHash, MIN_SIZE) == 0) {
        printf("Acknowledgment is valid!\n");
        printf(localHash, receivedHash);
        Write_File("Acknowledgment.txt", "Acknowledgment Successful");
    } else {
        printf("Acknowledgment is invalid!\n");
        Write_File("Acknowledgment.txt", "Acknowledgment Failed");
    }
    free(secretKey);
    free(localHash);
    free(message);
    free(seed);
    printf("Message: ");
    for (int i = 0; i < MIN_SIZE; i++) {
        printf("%c", message[i]);
    }
    printf("\n");
    printf("Seed: ");
    for (int i = 0; i < MIN_SIZE; i++) {
        printf("%02x", seed[i]);  // print in hex format
    }
    printf("\n");
    return 0;
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
void Convert_to_Hex(char output[], unsigned char input[], int inputlength) { //Function to convert to hex
	for (int i=0; i<inputlength; i++){
		sprintf(&output[2*i], "%02x", input[i]);
	}
}
void Send_via_ZMQ(unsigned char send[], int sendlen) //Function to send using zmq to bob
{
	void *context = zmq_ctx_new ();					            
    void *requester = zmq_socket (context, ZMQ_REQ);		    
   	printf("Connecting to Bob and sending the message...\n");
    zmq_connect (requester, "tcp://localhost:5555");		   
    zmq_send (requester, send, sendlen, 0);			    	
    zmq_close (requester);						              
    zmq_ctx_destroy (context);					               
}
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen) //Hash sha crypto function
{
    unsigned char *hash_result = (unsigned char*) malloc(inputlen);
    hash_state md;                                                       
    sha256_init(&md);                                                      
    sha256_process(&md, (const unsigned char*)input, inputlen);            
    sha256_done(&md, hash_result);                                        
    return hash_result;
}
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit) //Function to receive from Bob using zmq
{
	void *context = zmq_ctx_new ();			        	                                
    void *responder = zmq_socket (context, ZMQ_REP);                                   
   	int rc = zmq_bind (responder, "tcp://*:5559");	                                	
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
void Write_File(char fileName[], char input[]) { //Function to write to file
    FILE *pFile;
    pFile = fopen(fileName, "w");
    if (pFile == NULL) {
        printf("Failed to open the file");
        exit(0);
    }
    fputs(input, pFile);
    fclose(pFile);
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
