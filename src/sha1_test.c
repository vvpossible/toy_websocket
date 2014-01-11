#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include <unistd.h>

#define TEST_STRING "gY+Nj1cbY60oX84X0a83Xw==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

extern int base64_encode(unsigned char* , int, unsigned char*);

int main()
{
    unsigned char sha_res[20];
    unsigned char base64[32];
    int i, len;

    SHA1Context sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *) TEST_STRING, strlen(TEST_STRING));

    if (!SHA1Result(&sha))
    {
        fprintf(stderr, "ERROR-- could not compute message digest\n");
    }
    else
    {
        printf( "%-8x %-8x %-8x %-8x %-8x\n",
                    sha.Message_Digest[0],
                    sha.Message_Digest[1],
                    sha.Message_Digest[2],
                    sha.Message_Digest[3],
                    sha.Message_Digest[4]);
        for(i = 0 ; i < 5 ; i++)
        {
            unsigned char* p = (unsigned char*)&(sha.Message_Digest[i]);
            sha_res[4*i] = p[3];
            sha_res[4*i+1]= p[2];
            sha_res[4*i+2] = p[1];
            sha_res[4*i+3] = p[0];
        }

        len = base64_encode(sha_res, 20, base64);

        write(0, base64, len);
    }
    return 0;
}

