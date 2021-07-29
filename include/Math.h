//
// Created by gaetan on 13/07/2020.
//

#ifndef TFHE_PROTOCOL_MATH_H
#define TFHE_PROTOCOL_MATH_H

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>
#include <tfhe/tfhe_core.h>

void bootsADD1bit(LweSample* result, LweSample* a, LweSample* b, LweSample* carry, const TFheGateBootstrappingCloudKeySet* cloud_key);
void bootsADDNbit(LweSample* result, LweSample* a, LweSample* b, LweSample* carry, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);

void bootsTwoSComplement(LweSample* result, LweSample* a, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);
void bootsABS(LweSample* result, LweSample* a, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);
void bootsSUBNbit(LweSample* result, LweSample* a, LweSample* b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);

void bootsShiftLeft(LweSample* result, LweSample* a, const int bitsize, const int n, const TFheGateBootstrappingCloudKeySet* cloud_key);
void bootsShiftRight(LweSample* result, LweSample* a, const int bitsize, const int n, const TFheGateBootstrappingCloudKeySet* cloud_key);

void bootsShiftLeftNR(LweSample* a, const int bitsize, const int n, const TFheGateBootstrappingCloudKeySet* cloud_key);

void bootsMultiply(LweSample* result, LweSample* a, LweSample* b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);

double approxEquals(Torus32 a, Torus32 b);
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk);
void minimum(LweSample* result, LweSample* bit, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);


uint64_t ManhattanDistance(std::vector<uint8_t> a, std::vector<uint8_t> b);
uint64_t ManhattanDistance64(std::vector<uint64_t> a, std::vector<uint64_t> b);
uint64_t EuclideanDistance(std::vector<uint8_t> a, std::vector<uint8_t> b);
uint64_t EuclideanDistance64(std::vector<uint64_t> a, std::vector<uint64_t> b);

void HE_ManhattanDistance(LweSample* result,  std::vector<LweSample*> a, std::vector<LweSample*> b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);
void HE_EuclideanDistance(LweSample* result, std::vector<LweSample*> a, std::vector<LweSample*> b, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);

void Function_f(LweSample* result_b, std::vector<LweSample*> a, std::vector<LweSample*> b, LweSample* bound_match, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);
void Function_g(LweSample* result, LweSample* result_b, LweSample* r0, LweSample* r1, const int bitsize, const TFheGateBootstrappingCloudKeySet* cloud_key);

/*
 * Plaintext domain
 */
uint64_t ADDNbit(uint64_t a, uint64_t b, const int bitsize);
uint64_t TwoSComplement(uint64_t a, const int bitsize);
uint64_t ABS(uint64_t a, const int bitsize);
uint64_t SUBNbit(uint64_t a, uint64_t b, const int bitsize);
uint64_t Multiply(uint64_t a, uint64_t b, const int bitsize);
uint64_t ManhattanDistanceBitwise(std::vector<uint64_t> a, std::vector<uint64_t> b, const int bitsize);
uint64_t EuclideanDistanceBitwise(std::vector<uint64_t> a, std::vector<uint64_t> b, const int bitsize);
uint64_t Function_f_clear(std::vector<uint64_t> a, std::vector<uint64_t> b, uint64_t bound_match_clear, const int bitsize);
uint64_t Function_g_clear(uint64_t result_b, uint64_t r0, uint64_t r1, const int bitsize);

//Ctxt HE_Manhatt
// anDistance (EncryptedArray ea, Ctxt ctxt_a, Ctxt ctxt_b);
//Ctxt HE_EuclideanDistance(EncryptedArray ea, Ctxt ctxt_a, Ctxt ctxt_b);
//
//Ctxt Distance_check(EncryptedArray ea, Ctxt d_a, long bound, bool b);
//Ctxt Function_g(EncryptedArray ea, Ctxt d_check, std::vector<long> r1, std::vector<long> r2);

void printSlot64(uint64_t n);

#endif //TFHE_PROTOCOL_MATH_H
