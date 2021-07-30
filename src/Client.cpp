#include "../include/Client.h"
#include <iostream>

using namespace std;

void printVector(vector<uint8_t > v, long size)
{
    printf("[");
    for (int i = 0; i < size; ++i)
    {
        printf("%u ", v[i]);
    }
    printf("]\n");
}


void printVect64(vector<uint64_t> v, uint64_t length){
    printf("[");
    for (int i = 0; i < length; ++i)
    {
        printf("%lu %ld ", v[i], v[i]);
        for (int j = 0; j < 64; ++j) {
            std::cout << ((v[i] >> j) & 1);
        }
        cout << endl;
    }
    printf("]\n");
}

