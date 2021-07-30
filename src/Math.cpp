#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <tfhe/tfhe_gate_bootstrapping_functions.h>
#include <iostream>
#include "../include/Math.h"

using namespace std;

void printSlot64(uint64_t n)
{
    printf("[");
    printf("%lu %ld ", n, n);
    for (int i = 0; i < 64; ++i) {
        std::cout << ((n >> i) & 1);
    }
    printf("]");
}

/*
 * Elementary operation on bits, such as addition substration etc.
 *
 */

// Addition of 1-bit sample
void bootsADD1bit(LweSample* result, LweSample* a, LweSample* b, LweSample* carry, const TFheGateBootstrappingCloudKeySet* cloud_key){
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    LweSample* init_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    bootsCOPY(&init_carry[0], carry, cloud_key);

    // Addition of the bits a, b and carry
    bootsXOR(&tmp[0], a, b, cloud_key);
    bootsXOR(result, &tmp[0], carry, cloud_key);

    // Update of the next carry
    bootsAND(&tmp[0], a, b, cloud_key);
    bootsCOPY(&tmp_carry[0], &tmp[0], cloud_key);
    bootsAND(&tmp[0], a, &init_carry[0], cloud_key);
    bootsXOR(carry, &tmp_carry[0], &tmp[0], cloud_key);
    bootsAND(&tmp[0], &init_carry[0], b, cloud_key);
    bootsXOR(&tmp_carry[0], carry, &tmp[0], cloud_key);
    bootsCOPY(carry, &tmp_carry[0], cloud_key);

    // Free
    delete_gate_bootstrapping_ciphertext_array(1, tmp);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
    delete_gate_bootstrapping_ciphertext_array(1, init_carry);
}

// Addition of multibit sample
// The carry in parameter is useful for the subtraction
void bootsADDNbit(LweSample* result, LweSample* a, LweSample* b, LweSample* carry, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key){

    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    //initialize the tmp_carry to 0
    bootsCONSTANT(&tmp_carry[0], 0, cloud_key);

    for (int i = 0; i < bitsize; ++i) {
        bootsADD1bit(&result[i], &a[i], &b[i], &tmp_carry[0], cloud_key);
    }
    bootsCOPY(&carry[0], &tmp_carry[0], cloud_key);

    // Free
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}


// Calcul of the 2's complement to do substraction
void bootsTwoSComplement(LweSample* result, LweSample* a, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key){
    LweSample* zero_one = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    //bootsCONSTANT(&zero_one[0], 0, cloud_key);
    bootsCONSTANT(&zero_one[0], 1, cloud_key);
    for (int i = 1; i < bitsize+1; ++i) {
        bootsCONSTANT(&zero_one[i], 0, cloud_key);
    }
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);


    //for 1st complement
    for (int i = 0; i < bitsize; ++i) {
        bootsXOR(&tmp[i], &a[i], &zero_one[0], cloud_key);
    }
    // for 2s complement, you need to add 1 to the 1st complement
    bootsADDNbit(result, tmp, zero_one, tmp_carry, bitsize, cloud_key);

    // Free
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, zero_one);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}

// Get the absolute value of a number
// in substraction, when this is used, bitsize is 9
void bootsABS(LweSample* result, LweSample* a, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key){
    LweSample* mask = new_gate_bootstrapping_ciphertext_array(bitsize, cloud_key->params);
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);

    //first the mask is created
    for (int i = 0; i < bitsize; ++i) {
        bootsCOPY(&mask[i], &a[bitsize-1], cloud_key);
    }

    // then the mask is added to the number
    bootsADDNbit(tmp, a, mask, tmp_carry, bitsize, cloud_key);

    //finally the previous intermediate result is XORed with the mask
    for (int i = 0; i < bitsize; ++i) {
        bootsXOR(&result[i], &tmp[i], &mask[i], cloud_key);
    }

    // Free
    delete_gate_bootstrapping_ciphertext_array(bitsize, mask);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}

// Calcul of the difference between a and b
// a is added with the two's complement of b
void bootsSUBNbit(LweSample* result, LweSample* a, LweSample* b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key){
    LweSample* b_2comp = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(bitsize+2, cloud_key->params);
    LweSample* a_long = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp2 = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp3 = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);

    //a is put to 9 bits, the 9th bits (most significant) will be the signing bit
    for (int i = 0; i < bitsize; ++i) {
        bootsCOPY(&a_long[i], &a[i], cloud_key);
    }
    bootsCONSTANT(&a_long[bitsize], 0, cloud_key); //a is positive for sure (see main.cpp) thus the signing bit is 0

    bootsTwoSComplement(b_2comp, b, bitsize, cloud_key); //the 2's complement is calculed on 8 bits
    bootsCONSTANT(&b_2comp[bitsize], 1, cloud_key); //the 9th bit is 1 as it is a negative number (b is positive, as for a)
    //then the addition between a and 2's(b) is done
    bootsADDNbit(tmp, a_long, b_2comp, tmp_carry,  bitsize+1, cloud_key);

    // If the final carry over the addition is 1, it is dropped and the result is positive (we let it as such)
    // If the final carry over the addition is 0, then two's complement of the sum is calculated as the sum is negative
    // Branching condition is too costly in the ciphertext domain, thus the following algorithm is applied

    //a_long is composed of 9 bits equal to carry that is called var
    for (int i = 0; i < bitsize+1; ++i) {
        bootsCOPY(&a_long[i], &tmp_carry[0], cloud_key);
    }

    // b_comp is NOT(var)
    for (int i = 0; i < bitsize+1; ++i) {
        bootsNOT(&b_2comp[i], &tmp_carry[0], cloud_key);
    }

    // tmp2 = tmp && NOT(var)
    for (int i = 0; i < bitsize+1; ++i) {
        bootsAND(&tmp2[i], &tmp[i], &b_2comp[i], cloud_key);
    }
    // tmp3 = 2's(tmp && NOT(var))
    bootsTwoSComplement(tmp3, tmp2, bitsize+1, cloud_key);

    //tmp2 = tmp && var
    for (int i = 0; i < bitsize+1; ++i) {
        bootsAND(&tmp2[i], &tmp[i], &a_long[i], cloud_key);
    }

    // res = tmp3 || tmp2
    for (int i = 0; i < bitsize+1; ++i) {
        bootsOR(&result[i], &tmp3[i], &tmp2[i], cloud_key);
    }

    // Free
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, b_2comp);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, a_long);
    delete_gate_bootstrapping_ciphertext_array(bitsize+2, tmp);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp2);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp3);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}

// Multiply a by pow(2,n), i.e. shift n bits to the left
void bootsShiftLeft(LweSample* result, LweSample* a, const int bitsize, const int n, const TFheGateBootstrappingCloudKeySet* cloud_key){
    for (int i = 0; i < n; ++i) {
        bootsCONSTANT(&result[i], 0, cloud_key);
    }
    for (int i = n; i < bitsize; ++i) {
        bootsCOPY(&result[i], &a[i-n], cloud_key);
    }
}

//Divide by pow(2,n), i.e. shift n bits to the right
void bootsShiftRight(LweSample* result, LweSample* a, const int bitsize, const int n, const TFheGateBootstrappingCloudKeySet* cloud_key){
    for (int i = 0; i < bitsize-n; ++i) {
        bootsCOPY(&result[i], &a[i+n] , cloud_key);
    }
    for (int i = bitsize-n; i < bitsize; ++i) {
        bootsCONSTANT(&result[i], 0, cloud_key);
    }
}

void bootsShiftLeftNR(LweSample* a, const int bitsize, const int n, const TFheGateBootstrappingCloudKeySet* cloud_key){
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(bitsize, cloud_key->params);
    for (int i = 0; i < bitsize; ++i) {
        bootsCOPY(&tmp[i], &a[i], cloud_key);
    }
    bootsShiftLeft(a, tmp, bitsize, n, cloud_key);

    // Free
    delete_gate_bootstrapping_ciphertext_array(bitsize, tmp);
}

// Naive multiplication a * b, could be great to implement Karatsuba
void bootsMultiply(LweSample* result, LweSample* a, LweSample* b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key) {

    int length = 23;//bitsize*2-1 // for the euclidean distance is bitsize *3 basically;
    LweSample* tmp_ongoing_sum = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
    LweSample* tmp_and_result = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
    LweSample* tmp_final_sum = new_gate_bootstrapping_ciphertext_array(length, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);

    for (int i = 0; i < length; ++i) {
        bootsCONSTANT(&tmp_final_sum[i], 0, cloud_key);
        bootsCONSTANT(&tmp_ongoing_sum[i], 0, cloud_key);
        bootsCONSTANT(&tmp_and_result[i], 0, cloud_key);
    }

    for (int i = 0; i < bitsize; ++i) {
        for (int j = 0; j < i ; ++j) {
            bootsCONSTANT(&tmp_and_result[j], 0, cloud_key);
        }
        for (int j = 0; j < bitsize; ++j) {
            bootsAND(&tmp_and_result[j+i], &a[j], &b[i], cloud_key);
            bootsCOPY(&tmp_ongoing_sum[j], &tmp_final_sum[j], cloud_key);
        }
        for (int j = bitsize; j < length; ++j) {
            bootsCOPY(&tmp_ongoing_sum[j], &tmp_final_sum[j], cloud_key);
        }
        bootsADDNbit(tmp_final_sum, tmp_and_result, tmp_ongoing_sum, tmp_carry, length-1, cloud_key);
    }
    for (int i = 0; i < length; ++i) {
        bootsCOPY(&result[i], &tmp_final_sum[i], cloud_key);
    }

    // Free
    delete_gate_bootstrapping_ciphertext_array(length, tmp_ongoing_sum);
    delete_gate_bootstrapping_ciphertext_array(length, tmp_and_result);
    delete_gate_bootstrapping_ciphertext_array(length, tmp_final_sum);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}


double approxEquals(Torus32 a, Torus32 b) { return abs(a - b) < 10; }

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return b
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// this function compares two multibit words, and puts the min in result
void minimum(LweSample* result, LweSample* bit, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the min and copy it to the result
    for (int i=0; i<nb_bits; i++) {
        bootsMUX(&result[i], &tmps[0], &b[i], &a[i], bk);
    }
    //in bit we put the bool output for the function f
    bootsCOPY(&bit[0], &tmps[0], bk);
    for (int i = 1; i < nb_bits; ++i)
    {
        bootsCONSTANT(&bit[i], 0, bk);
    }
    delete_gate_bootstrapping_ciphertext_array(2, tmps);
}

/*
 * Calcul of the Manhattan Distance between two ciphertexts (b - a)
 * The result is in the [nslots-1] slot of the decrypted ciphertext "result"
 * For now, this is not robust. If some coefficients of ctxt_b decrypted are smaller than those of ctxt_a,
 * then the result is negative, then exponentiate and then wrong. Need to do something about it
 */
void HE_ManhattanDistance(LweSample* result, vector<LweSample*> a, vector<LweSample*> b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key) {
    if (a.empty())
        perror("One of the ciphertext is empty in a Manhattan distance\n");
    if (b.empty())
        perror("One of the ciphertext is empty in a Manhattan distance\n");
    if (a.size() != b.size())
        perror("The two ciphertexts do not have the same size in a Manhattan distance\n");


    int nb_samples = a.size();

    LweSample* tmp_diff = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp_sum = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);


    for (int i = 0; i < bitsize+1; ++i) {
        bootsCONSTANT(&tmp_diff[i], 0, cloud_key);
        bootsCONSTANT(&tmp_sum[i], 0, cloud_key);
    }

    for (int i=0; i < nb_samples; i++){
        bootsSUBNbit(tmp_diff, b[i], a[i], bitsize, cloud_key);
        for (int j = 0; j < bitsize+1; ++j) {
            bootsCOPY(&tmp_sum[j], &result[j], cloud_key);
        }
        bootsADDNbit(result, tmp_diff, tmp_sum, tmp_carry, bitsize, cloud_key);
    }

    // Free
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp_diff);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp_sum);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}

/*
 * Calcul of the square Euclidean Distance between two ciphertexts
 * Lacks of correctness again
 */
void HE_EuclideanDistance(LweSample* result, vector<LweSample*> a, vector<LweSample*> b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key){
    if (a.empty())
        perror("One of the ciphertext is empty in a Manhattan distance\n");
    if (b.empty())
        perror("One of the ciphertext is empty in a Manhattan distance\n");
    if (a.size() != b.size())
        perror("The two ciphertexts do not have the same size in a Manhattan distance\n");

    int nb_samples = a.size();
    const int max_bitsize = 24;

    LweSample* tmp_diff = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp_diff2 = new_gate_bootstrapping_ciphertext_array(bitsize+1, cloud_key->params);
    LweSample* tmp_square = new_gate_bootstrapping_ciphertext_array(max_bitsize, cloud_key->params);// checker si le 23 match bien avec la fonction multiply
    LweSample* tmp_sum = new_gate_bootstrapping_ciphertext_array(max_bitsize, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);


    for (int i=0; i < nb_samples; i++){
        bootsSUBNbit(tmp_diff, b[i], a[i], bitsize, cloud_key);
        for (int j = 0; j < bitsize+1; ++j) {
            bootsCOPY(&tmp_diff2[j], &tmp_diff[j], cloud_key);
        }
        bootsMultiply(tmp_square, tmp_diff, tmp_diff2, bitsize, cloud_key);
        for (int j = 0; j < max_bitsize-1; ++j) {
            bootsCOPY(&tmp_sum[j], &result[j], cloud_key);
        }
        bootsADDNbit(result, tmp_square, tmp_sum, tmp_carry, max_bitsize-1, cloud_key);
    }

    // Free
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp_diff);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, tmp_diff2);
    delete_gate_bootstrapping_ciphertext_array(max_bitsize, tmp_square);
    delete_gate_bootstrapping_ciphertext_array(max_bitsize, tmp_sum);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}


/*
 * Functions of the protocol P
 *
 *
 */

// f(s, t) = b
void Function_f(LweSample* result_b, vector<LweSample*> a, vector<LweSample*> b, LweSample* bound_match, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key)
{
    LweSample* ed = new_gate_bootstrapping_ciphertext_array(bitsize*3, cloud_key->params);
    LweSample* tmp_min = new_gate_bootstrapping_ciphertext_array(bitsize*3, cloud_key->params);
    HE_EuclideanDistance(ed, a, b, bitsize, cloud_key);
    minimum(tmp_min, result_b, ed, bound_match, bitsize*3, cloud_key);
    delete_gate_bootstrapping_ciphertext_array(bitsize*3, ed);
    delete_gate_bootstrapping_ciphertext_array(bitsize*3, tmp_min);
}

// g(b, r0, r1) = (1 - b) * r0 + b * r1
void Function_g(LweSample* result, LweSample* result_b, LweSample* r0, LweSample* r1, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key)
{
    LweSample* one = new_gate_bootstrapping_ciphertext_array(bitsize, cloud_key->params);
    LweSample* tmp_carry = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    bootsCONSTANT(&one[0], 1, cloud_key);
    for (int i = 1; i < bitsize; ++i)
    {
        bootsCONSTANT(&one[i], 0, cloud_key);
    }
    LweSample* tmp_r0 = new_gate_bootstrapping_ciphertext_array(bitsize, cloud_key->params);
    // (1 - b)
    bootsSUBNbit(tmp_r0, one, result_b, bitsize, cloud_key);
    //(1 - b) * r0
    LweSample* tmp_result = new_gate_bootstrapping_ciphertext_array(bitsize*3, cloud_key->params);
    bootsMultiply(tmp_result, tmp_r0, r0, bitsize, cloud_key);
    for (int i = 0; i < bitsize; ++i) {
        bootsCOPY(&tmp_r0[i], &tmp_result[i], cloud_key);
    }
    // b * r1
    bootsMultiply(tmp_result, result_b, r1, bitsize, cloud_key);
    // (1 - b) * r0 + b * r1
    bootsADDNbit(result, tmp_r0, tmp_result, tmp_carry, bitsize, cloud_key);

    delete_gate_bootstrapping_ciphertext_array(bitsize, one);
    delete_gate_bootstrapping_ciphertext_array(bitsize, tmp_r0);
    delete_gate_bootstrapping_ciphertext_array(bitsize*3, tmp_result);
    delete_gate_bootstrapping_ciphertext_array(1, tmp_carry);
}


/*
 * CODE ON PLAINTEXTS
 *
 *
 */

// Addition of multibit sample
uint64_t ADDNbit(uint64_t a, uint64_t b, const int bitsize){
    uint64_t one = 1;
    for (int i = 0; i <= bitsize; ++i) {
        uint64_t carry = a & b;
        a ^= b;
        b = carry << one;
    }
    return a;
}


// Calcul of the 2's completement to do substraction
uint64_t TwoSComplement(uint64_t a, const int bitsize){
    uint64_t one = 1;
    for (int i = 0; i < bitsize; ++i) {
        a = (a ^ (one << i));
    }
    uint64_t tmp = ADDNbit(a, one, bitsize);
    return tmp;
}

// Calcul of the absolute value
uint64_t ABS(uint64_t a, const int bitsize){
    uint64_t bitsize_64 = bitsize-1;
    uint64_t tmp = (a >> bitsize_64);
    uint64_t mask = 0;
    for (int i = 0; i < bitsize; ++i) {
        mask = (mask ^ (tmp << i));
    }
    tmp = ADDNbit(a, mask, bitsize);
    return (tmp ^ mask);
}

// Cal of the subtraction
uint64_t SUBNbit(uint64_t a, uint64_t b, const int bitsize){
    uint64_t b_comp = TwoSComplement(b, bitsize);
    uint64_t tmp = ADDNbit(a, b_comp, bitsize);
    b_comp = ABS(tmp, bitsize);
    return b_comp;
}

// Naive multiplication a * b, could be great to implement Karatsuba
uint64_t Multiply(uint64_t a, uint64_t b, const int bitsize) {
    uint64_t bitsize_64 = 64;
    uint64_t one = 1;
    uint64_t tmp_ongoing_sum = 0, tmp_and_result = 0, tmp_final_sum = 0;

    for (int i = 0; i < bitsize; ++i) {
        uint64_t tmp = b;
        tmp = tmp << (bitsize_64 - one - i);
        tmp = tmp >> (bitsize_64 - one);
        uint64_t tmp_b = 0;
        for (int j = 0; j < bitsize; ++j) {
            tmp_b = (tmp_b ^ (tmp << j));
        }
        tmp_and_result = a & tmp_b;
        tmp_and_result = tmp_and_result << i;
        tmp_ongoing_sum = tmp_final_sum;
        tmp_final_sum = ADDNbit(tmp_and_result, tmp_ongoing_sum, bitsize_64);
    }
    return tmp_final_sum;
}

/*
* Calcul of the Manhattan Distance between two vectors of long, i.e. plaintexts
*/
uint64_t ManhattanDistance(vector<uint8_t> a, vector<uint8_t> b) {
    if (a.size() != b.size())
        perror("Manhattan Distance between two vectors of different sizes.\n");

    long result = 0;
    for(int i = 0; i < a.size(); i++)
        result += labs(a[i] - b[i]);
    return result;
}

/*
 * Calcul of the Manhattan Distance between two vectors of numbers coded on 64 bits, i.e. plaintexts
 */
uint64_t ManhattanDistance64(vector<uint64_t> a, vector<uint64_t> b) {
    if (a.size() != b.size())
        perror("Manhattan Distance between two vectors of different sizes.\n");

    long result = 0;
    for(int i = 0; i < a.size(); i++)
        result += labs(a[i] - b[i]);
    return result;
}

/*
 * Calcul of the square Euclidean Distance between two vectors of long, i.e. plaintexts
 * The square root at the end is not executed as the equivalent operation on encrypted ciphertexts is too costly
 */
uint64_t EuclideanDistance(vector<uint8_t> a, vector<uint8_t> b) {
    if (a.size() != b.size())
        perror("Euclidean Distance between two vectors of different sizes.\n");

    long result =0;
    for (int i = 0; i < a.size() ; ++i)
        result += powl(a[i] - b[i], 2);
    //result = sqrtl(result);
    return result;
}

/*
 * Calcul of the square Euclidean Distance between two vectors of numbers coded on 64 bits, i.e. plaintexts
 * The square root at the end is not executed as the equivalent operation on encrypted ciphertexts is too costly
 */
uint64_t EuclideanDistance64(vector<uint64_t> a, vector<uint64_t> b) {
    if (a.size() != b.size())
        perror("Euclidean Distance between two vectors of different sizes.\n");

    long result =0;
    for (int i = 0; i < a.size() ; ++i)
        result += powl(a[i] - b[i], 2);
    //result = sqrtl(result);
    return result;
}

uint64_t ManhattanDistanceBitwise(vector<uint64_t> a, vector<uint64_t> b, const int bitsize){
    uint64_t result = 0;

    for (int i=0; i < a.size(); i++) {
        uint64_t tmp_diff = SUBNbit(b[i], a[i], bitsize);
        uint64_t tmp_abs = ABS(tmp_diff, bitsize);
        uint64_t tmp_sum = result;
        result = ADDNbit(tmp_abs, tmp_sum, bitsize);
    }
    return result;
}

uint64_t EuclideanDistanceBitwise(vector<uint64_t> a, vector<uint64_t> b, const int bitsize){
    uint64_t result = 0;

    for (int i=0; i < a.size(); i++) {
        uint64_t tmp_diff = SUBNbit(b[i], a[i], bitsize);
        uint64_t tmp_square = Multiply(tmp_diff, tmp_diff, 8);
        uint64_t tmp_sum = result;
        result = ADDNbit(tmp_square, tmp_sum, bitsize);
    }
    return result;
}

// f(s, t) = b
uint64_t Function_f_clear(vector<uint64_t> a, vector<uint64_t> b, uint64_t bound_match_clear, const int bitsize)
{
    uint64_t one = 1;
    uint64_t zero = 0;
    uint64_t ed = EuclideanDistanceBitwise(a, b, bitsize);
    if (ed <= bound_match_clear)
        return one;
    else
        return zero;
}

// g(b, r0, r1) = (1 - b) * r0 + b * r1
uint64_t Function_g_clear(uint64_t result_b, uint64_t r0, uint64_t r1, const int bitsize)
{
    uint64_t one = 1;
    return ((one-result_b)*r0 + result_b*r1);
}
