#include<stdio.h>

static char* c_map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const unsigned char* in, int len, unsigned char* out)
{
    int i, j,state;
    unsigned char rem;

    for(i = j = state = 0 ; i < len ; i++)
    {
        switch(state)
        {
        case 0:
            out[j++] = c_map[in[i]>>2];
            rem = in[i] & 0x3;
            if(i+1 >= len)
            {
                out[j++] = c_map[rem<<4];
                out[j++] = '=';
                out[j++] = '=';
                return j;
            }
            else
                state = 1;
        break;

        case 1:
            out[j++] = c_map[rem<<4 | in[i]>>4];
            rem = in[i] & 0xf;
            if(i+1 >= len)
            {
                out[j++] = c_map[rem<<2];
                out[j++] = '=';
                return j;
            }
            else
                state = 2;
        break;

        case 2:
            out[j++] = c_map[rem<<2 | in[i]>>6];
            out[j++] = c_map[in[i]&0x3f];
            state = 0;
        break;

        default:
        break;
        }
    }
    return j;
}

