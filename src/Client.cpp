//
// Created by gaetan on 01/07/2020.
//

#include <iostream>
#include <sstream>
#include "../include/Client.h"
#include "../include/Math.h"
#include <chrono>

using namespace std;

typedef chrono::high_resolution_clock Clock;

void printVector(vector<uint8_t> v, long size)
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


int main(void)
{

//    uint8_t bit = 9;
//    for (int k = 0; k < 8; ++k) {
//        printf("%u ", (bit>>k)&1);
//    }
//    printf("\n\n");

    unsigned short int ID = 007; //The unique IDentifier of a Client
    const int minimum_lambda = 128;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda); //The params, public, important for ?? homomorphic operation, in particular generating keys and bootstrapping.
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);  //The secret key associated with the Client with the particular ID
    const TFheGateBootstrappingCloudKeySet* cloud_key = &key->cloud;

    // Create 3 vectors of long with nslots elements for test
    cout << "Creation of the test vectors" << endl;
    static const uint32_t nslots = 128;
    static const uint32_t bitsize = 8; // 1 bit for parity, the others for a number between 0 and 255
    static const uint32_t max_bitsize = 24; // this will be on 24 bits, in order to ensure correctness of the euclidian distance, its actually 23 bits +1 to do the two's complement
    int space_msg = 256;
    //int torus_msg = 256;
    Torus32 message, phase, dec_message;
    static const double alpha = pow(2., -20);//1. / (10. * bitsize);
    vector<uint8_t> template_client(nslots);
    vector<uint8_t> sample_client_true(nslots);
    vector<uint8_t> sample_client_false(nslots);
    srand(time(NULL));
//    int r1 = rand() %nslots;
    // Set it with numbers 0..nslots - 1
    for (int i = 0; i < nslots; ++i) {
//        template_client[i] = 248;
//        sample_client_true[i] = 210;

        template_client[i] = i; //rand() %256;
        sample_client_true[i] = i+13;
//        sample_client_false[nslots-i-1] = (template_client[i]+1)*i-1;
        srand(time(NULL)+i);
        sample_client_false[i] = rand() %256;
//        if (i%2==0) {
//            srand(time(NULL)+3*i+2);
//            sample_client_true[i] = rand() %256;
//
//        }
//        else {
//            srand(time(NULL)+48*i-3);
//            sample_client_true[i] = rand();
//        }
    }
    cout << "template_client" << endl;
    printVector(template_client, nslots);
    cout << "sample_client_true" << endl;
    printVector(sample_client_true, nslots);
    cout << "sample_client_false" << endl;
    printVector(sample_client_false, nslots);

    // Test of correctness of encryption and decryption
    cout << "Test of correctness of encryption/decryption\nCreation of the encrypted test vectors" << endl;
    vector<LweSample*> enc_template_client(nslots);
    vector<LweSample*> enc_sample_client_true(nslots);
    vector<LweSample*> enc_sample_client_false(nslots);
    for (int i = 0; i < nslots; i++) {
        enc_template_client[i] = new_gate_bootstrapping_ciphertext_array(bitsize, params);
        enc_sample_client_true[i] = new_gate_bootstrapping_ciphertext_array(bitsize, params);
        enc_sample_client_false[i] = new_gate_bootstrapping_ciphertext_array(bitsize, params);
//       cout << (100./nslots)*(i+1) << "% encryption done" << endl;
        for (int j=0; j < bitsize; j++) {
            uint8_t mu = template_client[i];
            bootsSymEncrypt(&enc_template_client[i][j], (mu>>j)&1, key);
            mu = sample_client_true[i];
            bootsSymEncrypt(&enc_sample_client_true[i][j], (mu>>j)&1, key);
            mu = sample_client_false[i];
            bootsSymEncrypt(&enc_sample_client_false[i][j], (mu>>j)&1, key);
        }
    }

    //decrypt
    cout << "Encryption done\nNow let's start decryption" << endl;
    vector<uint8_t>  dec_template_client(nslots);
    vector<uint8_t>  dec_sample_client_true(nslots);
    vector<uint8_t>  dec_sample_client_false(nslots);
    for (int i = 0; i < nslots; i++) {
        cout << (100./nslots)*(i+1) << "% decryption done" << endl;
        for (int j = 0; j < bitsize; j++) {
            uint8_t dec_mu = bootsSymDecrypt(&enc_template_client[i][j], key);
            dec_template_client[i] |= (dec_mu<<j);
            dec_mu = bootsSymDecrypt(&enc_sample_client_true[i][j], key);
            dec_sample_client_true[i] |= (dec_mu<<j);
            dec_mu = bootsSymDecrypt(&enc_sample_client_false[i][j], key);
            dec_sample_client_false[i] |= (dec_mu<<j);
        }
    }
    cout << "Decryption done\nLet's print the vectors" << endl;
    printVector(dec_template_client, nslots);
    cout << "template_client" << endl;
    printVector(dec_sample_client_true, nslots);
    cout << "sample_client_true" << endl;
    printVector(dec_sample_client_false, nslots);
    cout << "sample_client_false" << endl;

    cout << "Correctness tests done\n" << endl;

    /*
     *
     * Tests for operations
     */
//    cout << "Let's tests all the subroutines\n" << endl;
//
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(max_bitsize, params);
    uint64_t tmp_result = 0;

//    cout << "Test of the addition of two n-bit numbers " << (int)template_client[4] << " + " << (int)template_client[8] << endl;
    auto t1 = Clock::now();
//    bootsADDNbit(tmp, enc_template_client[4], enc_template_client[8], bitsize, cloud_key);
    auto t2 = Clock::now();
//    cout << "Addition n-bit: "
//              << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//              << " milliseconds" << endl;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %u\n", tmp_result, template_client[4]+template_client[8]);

//    cout << "Test of the addition of two n-bit numbers " << (int)sample_client_true[4] << " + " << (int)sample_client_true[8] << endl;
//    tmp_result = 0;
//    t1 = Clock::now();
//    bootsADDNbit(tmp, enc_sample_client_true[4], enc_sample_client_true[8], bitsize, cloud_key);
//    t2 = Clock::now();
//    cout << "Addition n-bit: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %u\n", tmp_result, sample_client_true[4]+sample_client_true[8]);
//
//    cout << "Test of the addition of two n-bit numbers " << (int)sample_client_false[4] << " + " << (int)sample_client_false[8] << endl;
//    tmp_result = 0;
//    t1 = Clock::now();
//    bootsADDNbit(tmp, enc_sample_client_false[4], enc_sample_client_false[8], bitsize, cloud_key);
//    t2 = Clock::now();
//    cout << "Addition n-bit: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %u\n", tmp_result, sample_client_false[4]+sample_client_false[8]);
//
//    cout << "Test of the subtraction of two n-bit numbers " << (int)template_client[4] << " - " << (int)template_client[8] << endl;
//    t1 = Clock::now();
//    bootsSUBNbit(tmp, enc_template_client[4], enc_template_client[8], bitsize, cloud_key);
//    t2 = Clock::now();
//    cout << "Subtraction n-bit: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be |%d|\n", tmp_result, template_client[4]-template_client[8]);
//
//    cout << "Test of the subtraction of two n-bit numbers: " << (int)template_client[8] << " - " << (int)template_client[4] << endl;
//    t1 = Clock::now();
//    bootsSUBNbit(tmp, enc_template_client[8], enc_template_client[4], bitsize, cloud_key);
//    t2 = Clock::now();
//    cout << "Subtraction n-bit: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be |%d|\n", tmp_result, template_client[8]-template_client[4]);
//
//    cout << "Test of the shift to the left of a n-bit number " << (int)template_client[8] << endl;
//    t1 = Clock::now();
//    bootsShiftLeft(tmp, enc_template_client[8], bitsize, 1, cloud_key);
//    t2 = Clock::now();
//    cout << "Shift left: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %u\n", tmp_result, template_client[8]<<1);
//
//    cout << "Test of the shift to the right of a n-bit number " << (int)template_client[8] << endl;
//    t1 = Clock::now();
//    bootsShiftRight(tmp, enc_template_client[8], bitsize, 1, cloud_key);
//    t2 = Clock::now();
//    cout << "Shift right: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %u\n", tmp_result, template_client[8]>>1);
//
//
//    for (int m = 0; m < max_bitsize; ++m) {
//        bootsCONSTANT(&tmp[m], 0, cloud_key);
//    }
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %d\n", tmp_result, 0);
//
//    cout << "Test of the multiplication of two n-bit numbers: " << (int)template_client[4] << " * " << (int)template_client[8] << endl;
//    t1 = Clock::now();
//    bootsMultiply(tmp, enc_template_client[4] ,enc_template_client[8], bitsize, cloud_key);
//    t2 = Clock::now();
//    cout << "Multiplication: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %d\n", tmp_result, template_client[4]*template_client[8]);
//
//    for (int m = 0; m < max_bitsize; ++m) {
//        bootsCONSTANT(&tmp[m], 0, cloud_key);
//    }
//
//    cout << "Test of the multiplication of two n-bit numbers: " << (int)sample_client_true[4] << " * " << (int)sample_client_true[8] << endl;
//    t1 = Clock::now();
//    bootsMultiply(tmp, enc_sample_client_true[4] ,enc_sample_client_true[8], bitsize, cloud_key);
//    t2 = Clock::now();
//    cout << "Multiplication: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %d\n", tmp_result, sample_client_true[4]*sample_client_true[8]);
//
//    for (int m = 0; m < max_bitsize; ++m) {
//        bootsCONSTANT(&tmp[m], 0, cloud_key);
//    }
//
//    cout << "Test of the multiplication of two n-bit numbers: " << (int)sample_client_false[4] << " * " << (int)sample_client_false[8] << endl;
//    t1 = Clock::now();
//    bootsMultiply(tmp, enc_sample_client_false[4] ,enc_sample_client_false[8], bitsize, cloud_key);
//    t2 = Clock::now();
//    cout << "Multiplication: "
//         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
//         << " milliseconds" << endl;
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result is %lu and should be %d\n", tmp_result, sample_client_false[4]*sample_client_false[8]);
//    delete_gate_bootstrapping_ciphertext_array(max_bitsize, tmp);

// ------------------------------------------------------
//   BEGINNING OF THE SUITE OF TESTS ON THE PLAINTEXT DOMAIN
// ------------------------------------------------------

    int bitsize64 = 64;

    vector<uint64_t> test(nslots);
    vector<uint64_t> test2(nslots);
    for (int i = 0; i < nslots; ++i) {
        if (i%2) {
            test[i] = i;
            test2[i] = (i+13)%256;
        }
        else {
            test[i] = i;
            test2[i] = (i+13)%256;
        }
    }
    printVect64(test, nslots);
    printVect64(test2, nslots);



// Addition bitwise

    int cnt = 0;
    int loop = 0;
    uint64_t res;
    for (int i = 0; i < loop; ++i) {
//        res=0;
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        srand(time(NULL)*i+1);
        int r2 = rand() %nslots;
//        int r1 = i, r2 = i;

//        if (i == 0) {
//            cout << "Test of the addition of 2 n-bit numbers ";
//            printSlot64(test[r1]);
//            cout << " + ";
//            printSlot64(test[r2]);
//            cout << endl;
            t1 = Clock::now();
//        }
        res = ADDNbit(test[r1], test[r2], bitsize64);
//        if (i == 0) {
            t2 = Clock::now();
            cout << "Addition n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() << " nanoseconds" << endl;
//        }
//        printf("The result is %ld and should be %d\n", res, test[r1] + test[r2]);
//        cout << "The result is ";
//        printSlot64(res);
//        cout << " and should be ";
//        printSlot64(test[r1]+test[r2]);
//        cout << endl;
        if (res == (test[r1] + test[r2]))
        {
            cnt++;
        }
    }
    cout << "Addition: " << cnt << " success, " << loop-cnt << " fails" << endl;

    // Two's complement
    cnt = 0;
    for (int i = 0; i < loop; ++i) {
//        res=0;
//        srand(time(NULL)*i^3);
//        int r1 = rand() %nslots;
        int r1 = i;

//        if (i == 0) {
//        cout << "Test of the two's complement of a n-bit numbers ";
//        printSlot64(test[r1]);
//        cout << endl;
        t1 = Clock::now();
//        }
        res = TwoSComplement(test[r1], 64);
//        if (i == 0) {
        t2 = Clock::now();
        cout << "Two's complement: " << chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() << " nanoseconds" << endl;
//        }
//        cout << "The result is ";
//        printSlot64(res);
//        cout << " and should be ";
//        printSlot64(-test[r1]);
//        cout << endl;
        if (res == -test[r1])
        {
            cnt++;
        }
    }
    cout << "Two's complement: " << cnt << " success, " << loop-cnt << " fails" << endl;

    // Absolute value
    cnt =0;
    for (int i = 0; i < loop; ++i) {
//        res=0;
//        srand(time(NULL)*i^3);
//        int r1 = rand() %nslots;
        int r1 = i;

//        if (i == 0) {
//        cout << "Test of the absolute value of a n-bit numbers ";
//        printSlot64(test[r1]);
//        cout << endl;
            t1 = Clock::now();
//        }
        res = ABS(test[r1], bitsize64);
//        if (i == 0) {
            t2 = Clock::now();
            cout << "Absolute n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() << " nanoseconds" << endl;
//        }
//        cout << "The result is ";
//        printSlot64(res);
//        cout << " and should be ";
//        printSlot64((uint64_t) i);
//        cout << endl;
        if (res == (uint64_t) i)
        {
            cnt++;
        }
    }
    cout << "Absolute value: " << cnt << " success, " << loop-cnt << " fails" << endl;

    // Subtraction n bits
    cnt = 0;
    for (int i = 0; i < loop; ++i) {
//        res=0;
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        srand(time(NULL)*i+1);
        int r2 = rand() %nslots;
//        int r1 = i, r2 = i;

//        if (i == 0) {
//        cout << "Test of the subtraction of 2 n-bit numbers ";
//        printSlot64(test[r1]);
//        cout << " - ";
//        printSlot64(test[r2]);
//        cout << endl;
        t1 = Clock::now();
//        }
        res = SUBNbit(test[r1], test[r2], bitsize64);
//        if (i == 0) {
        t2 = Clock::now();
        cout << "Subtraction n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() << " nanoseconds" << endl;
        uint64_t tmp_res = ABS(test[r1] - test[r2], bitsize64);
//        cout << "The result is ";
//        printSlot64(res);
//        cout << " and should be ";
//        printSlot64(tmp_res);
//        cout << endl;
        if (res == tmp_res)
        {
            cnt++;
        }
    }
    cout << "Subtraction: " << cnt << " success, " << loop-cnt << " fails" << endl;

    // Multiplication of two n-bit numbers
    cnt=0;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        srand(time(NULL)*i+1);
        int r2 = rand() %nslots;
//        int r1 = i, r2 = i;
//        if (i == 0) {
//        cout << "Test of the multiplication of two n-bit numbers ";
//        printSlot64(test[r1]);
//        cout << " x ";
//        printSlot64(test[r2]);
//        cout << endl;
        t1 = Clock::now();
//        }
        res = Multiply(test[r1], test[r2], bitsize);
//        if (i == 0) {
        t2 = Clock::now();
        cout << "Multiplication n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() << " nanoseconds" << endl;
//        }
//        cout << "The result is ";
//        printSlot64(res);
//        cout << " and should be ";
//        printSlot64(test[r1]*test[r2]);
//        cout << endl;
        if (res == test[r1]*test[r2])
        {
            cnt++;
        }
    }
    cout << "Multiplication: " << cnt << " success, " << loop-cnt << " fails" << endl;

    // Manhattan distance of two vectors
    cnt=0;
    cout << "Test of the Manhattan distance between test and test1 above" << endl;
    t1 = Clock::now();
    res = ManhattanDistanceBitwise(test, test2, bitsize64);
    t2 = Clock::now();
    cout << "Manhattan distance bitwise: " << chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() << " nanoseconds" << endl;
    cout << "The result is ";
    printSlot64(res);
    cout << " and should be ";
    tmp_result = ManhattanDistance(template_client, sample_client_true);
    printSlot64(tmp_result);
    cout << endl;
    if (res == tmp_result)
        cnt++;
    cout << "Manhattan distance bitwise: " << cnt << " success, " << 1-cnt << " fails" << endl;


    // Euclidean distance of two vectors
        cnt=0;
        cout << "Test of the euclidean distance between test and test1 above" << endl;
        t1 = Clock::now();
        res = EuclideanDistanceBitwise(test, test2, bitsize64);
        t2 = Clock::now();
        cout << "Euclidean distance bitwise: " << chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() << " nanoseconds" << endl;
        cout << "The result is ";
        printSlot64(res);
        cout << " and should be ";
        tmp_result = EuclideanDistance(template_client, sample_client_true);
        printSlot64(tmp_result);
        cout << endl;
        if (res == tmp_result)
            cnt++;
        cout << "Euclidean distance bitwise: " << cnt << " success, " << 1-cnt << " fails" << endl;

     /*
     * The final test of the protocol
     */
    cout << "\n------------------------\nFinally we can try the protocol!" << endl;
    uint64_t bound_match_clear = 1000000; // arbitrary choice
    t1 = Clock::now();
    // Generation of the random numbers
    srand(time(NULL));
    uint64_t r0_clear = rand()%256;
    srand(time(NULL)*(r0_clear+1));
    uint64_t r1_clear = rand()%256;
    auto t3 = Clock::now();
    uint64_t result_b = Function_f_clear(test, test2, bound_match_clear, bitsize64);
    auto t4 = Clock::now();
    cout << "Function f bitwise: " << chrono::duration_cast<chrono::microseconds>(t4 - t3).count() << " microseconds" << endl;
    t3 = Clock::now();
    uint64_t y_clear = Function_g_clear(result_b, r0_clear, r1_clear, bitsize64);
    t4 = Clock::now();
    cout << "Function g bitwise: " << chrono::duration_cast<chrono::microseconds>(t4 - t3).count() << " microseconds" << endl;
    if (y_clear == r1_clear)
        cout << "Client successfully authenticated to the server!" << endl;
    else
        cout << "Client could not authenticate to the server!" << endl;
    t2 = Clock::now();
    cout << "Protocol P bitwise: " << chrono::duration_cast<chrono::microseconds>(t2 - t1).count() << " microseconds" << endl;

// ------------------------------------------------------
//   BEGINNING OF THE SUITE OF TESTS ON THE CIPHERTEXT DOMAIN
// ------------------------------------------------------
    cnt = 0;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2+1);
        int r2 = rand() %nslots;
//        int r1 = i, r2 = i;
        for (int i = 1; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }

//        if (i == 0) {
            cout << "Test of the addition of 2 n-bit numbers " << (int) sample_client_true[r1] << " + "
                 << (int) template_client[r2] << endl;
            t1 = Clock::now();
//        }
        bootsADDNbit(tmp, enc_sample_client_true[r1], enc_template_client[r2], bitsize, cloud_key);
//        if (i == 0) {
            t2 = Clock::now();
            cout << "Addition n-bit: "
                 << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
                 << " seconds" << endl;
//        }
                tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        printf("The result is %ld and should be %d\n", tmp_result, sample_client_true[r1] + template_client[r2]);
        if (tmp_result == (sample_client_true[r1] + template_client[r2]))
        {
            cnt++;
        }
    }
    cout << cnt << " success, " << loop-cnt << " fails" << endl;

    cnt=0;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2);
        int r2 = rand() %nslots;
//        int r1 = i, r2 = i;
//        if (i == 0) {
        cout << "Test of the two's complement of a n-bit numbers " << (int) sample_client_false[r1] << endl;
            t1 = Clock::now();
//        }
        bootsTwoSComplement(tmp, enc_sample_client_false[r1], bitsize, cloud_key);
//        if (i == 0) {
            t2 = Clock::now();
            cout << "Two's complement n-bit: "
                 << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
                 << " seconds" << endl;
//        }
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        printf("The result is %ld and should be %d\n", tmp_result, 256-sample_client_false[r1]);
        if (tmp_result == (256-sample_client_false[r1]))
        {
            cnt++;
        }
    }
    cout << cnt << " success, " << loop-cnt << " fails" << endl;

    cnt =0;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2);
        int r2 = rand() %nslots;
//        int r1 = i, r2 = i;

//        if (i == 0) {
        cout << "Test of the absolute value of a n-bit numbers " << (int) sample_client_false[r1] << endl;
            t1 = Clock::now();
//        }
        bootsABS(tmp, enc_sample_client_false[r1], bitsize, cloud_key);
//        if (i == 0) {
            t2 = Clock::now();
            cout << "Absolute n-bit: "
                 << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
                 << " seconds" << endl;
//        }
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        printf("The result is %ld and should be %d\n", tmp_result, sample_client_false[r1]);
        if (tmp_result == sample_client_false[r1])
        {
            cnt++;
        }
    }
    cout << cnt << " success, " << loop-cnt << " fails" << endl;

    cnt=0;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2);
        int r2 = rand() %nslots;
//        int r1 =i, r2 = i;

        for (int i = 0; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }

//        if (i == 0) {
        cout << "Test of the subtraction of two n-bit numbers " << (int) sample_client_true[r1] << " - "
             << (int) template_client[r2] << endl;
            t1 = Clock::now();
//        }
        bootsSUBNbit(tmp, enc_sample_client_true[r1], enc_template_client[r2], bitsize, cloud_key);
//        if (i == 0) {
            t2 = Clock::now();
            cout << "Subtraction n-bit: "
                 << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
                 << " seconds" << endl;
//        }
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        printf("The result is %lu and should be |%d|\n", tmp_result, sample_client_true[r1] - template_client[r2]);
        if (tmp_result == (sample_client_true[r1] - template_client[r2]))
        {
            cnt++;
        }
    }
    cout << cnt << " success, " << loop-cnt << " fails" << endl;

    cnt=0;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2);
        int r2 = rand() %nslots;
//        int r1 =i, r2 = i;

        for (int i = 0; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }

//        if (i == 0) {
        cout << "Test of the multiplication of two n-bit numbers " << (int) sample_client_true[r1] << " x "
             << (int) template_client[r2] << endl;
        t1 = Clock::now();
//        }
        bootsMultiply(tmp, enc_sample_client_true[r1], enc_template_client[r2], bitsize, cloud_key);
//        if (i == 0) {
        t2 = Clock::now();
        cout << "Multiplication n-bit: "
             << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
             << " seconds" << endl;
//        }
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        printf("The result is %lu and should be %d\n", tmp_result, sample_client_true[r1] * template_client[r2]);
        if (tmp_result == (sample_client_true[r1] * template_client[r2]))
        {
            cnt++;
        }
    }
    cout << cnt << " success, " << loop-cnt << " fails" << endl;
    /*
    * Test of distance
    */
//    cout << "Now we test the distances" << endl;
    LweSample* tmp_dist = new_gate_bootstrapping_ciphertext_array(max_bitsize, params);
    tmp_result = 0;

    cout << "Test of the manhattan distance between two vectors of n-bit numbers" << endl;
    cout << "Vector 1" << endl;
    printVector(template_client, nslots);
    cout << endl <<"Vector 2" << endl;
    printVector(sample_client_true, nslots);
    cout << endl;
    uint64_t mh =  ManhattanDistance(template_client, sample_client_true);
    uint64_t eh =  EuclideanDistance(template_client, sample_client_true);
//    cout << "The result shall be as follows: mh est " << mh << " et eh est " << eh << endl;
    for (int i = 0; i < max_bitsize; ++i) {
        bootsCONSTANT(&tmp_dist[i], 0, cloud_key);
    }
    t1 = Clock::now();
    HE_ManhattanDistance(tmp_dist, enc_template_client, enc_sample_client_true, bitsize, cloud_key);
    t2 = Clock::now();
    cout << "Manhattan distance: "
              << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
              << " seconds" << endl;
    for (int m = 0; m < max_bitsize; ++m) {
        uint8_t dec_mu = bootsSymDecrypt(&tmp_dist[m], key);
        tmp_result |= (dec_mu<<m);
    }
    printf("The result for Manhattan distance is %lu and should be %lu\n", tmp_result, mh);
    tmp_result = 0;
    for (int m = 0; m < max_bitsize; ++m) {
        bootsCONSTANT(&tmp_dist[m], 0, cloud_key);
    }

    cout << "Test of the euclidean distance between two vectors of n-bit numbers" << endl;
    cout << "Vector 1" << endl;
    printVector(template_client, nslots);
    cout << endl <<"Vector 2" << endl;
    printVector(sample_client_true, nslots);
    cout << endl;
    t1 = Clock::now();
    HE_EuclideanDistance(tmp_dist, enc_template_client, enc_sample_client_true, bitsize, cloud_key);
    t2 = Clock::now();
    cout << "Euclidean distance: "
              << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
              << " seconds" << endl;
    for (int m = 0; m < max_bitsize; ++m) {
        uint8_t dec_mu = bootsSymDecrypt(&tmp_dist[m], key);
        tmp_result |= (dec_mu<<m);
    }
    printf("The result for Euclidean distance is %lu and should be %lu\n", tmp_result, eh);


    /*
     * The final test of the protocol
     */
    cout << "\n------------------------\nFinally we can try the protocol!" << endl;
    for (int i = 0; i < max_bitsize; ++i) {
        bootsCONSTANT(&tmp_dist[i], 0, cloud_key);
    }
    int bound_match = 100; // arbitrary choice
    LweSample* enc_bound_match = new_gate_bootstrapping_ciphertext_array(max_bitsize, params);
    for (int i=0; i < max_bitsize; i++) {
        uint8_t mu = bound_match;
        bootsSymEncrypt(&enc_bound_match[i], (mu>>i)&1, key);
    }

    eh =  EuclideanDistance(template_client, sample_client_true);
    if (eh <= 10000)
        cout << "The Euclidean Distance is " << eh << " thus the client shall be authenticated" << endl;
    else
        cout << "The Euclidean Distance is " << eh << " thus the client shall not be authenticated" << endl;

    t1 = Clock::now();


    Client_C client(ID, key, enc_sample_client_true, nslots, minimum_lambda, params ,cloud_key, sample_client_true);
    //HE_EuclideanDistance(tmp_dist, client.getCtxt(), enc_template_client, bitsize, client.getCloudKey());
    //uint64_t eh =  EuclideanDistance(template_client, sample_client_true);
    // function to check if distance is lower than
//    tmp_result = 0;
//    for (int m = 0; m < max_bitsize; ++m) {
//        uint8_t dec_mu = bootsSymDecrypt(&tmp_dist[m], key);
//        tmp_result |= (dec_mu<<m);
//    }
//    printf("The result for Euclidean distance is %lu and should be %lu\n", tmp_result, eh);

    // Function f
    LweSample* enc_b = new_gate_bootstrapping_ciphertext_array(max_bitsize, params);
    t3 = Clock::now();
    Function_f(enc_b, client.getCtxt(), enc_template_client, enc_bound_match, bitsize, cloud_key);
    t4 = Clock::now();
    cout << "Function f: "
         << chrono::duration_cast<chrono::seconds>(t4 - t3).count()
         << " seconds" << endl;

    // Generation of the random numbers
    srand(time(NULL));
    uint64_t r0 = rand() %256;
    srand(time(NULL)*(r0+1));
    uint64_t r1 = rand() %256;

    // Encryption of the random numbers
    LweSample* enc_r0 = new_gate_bootstrapping_ciphertext_array(bitsize, params);
    LweSample* enc_r1 = new_gate_bootstrapping_ciphertext_array(bitsize, params);
    for (int i=0; i < bitsize; i++) {
        uint8_t mu = r0;
        bootsSymEncrypt(&enc_r0[i], (mu>>i)&1, key);
        mu = r1;
        bootsSymEncrypt(&enc_r1[i], (mu>>i)&1, key);
    }

    // Function g
    LweSample* enc_y = new_gate_bootstrapping_ciphertext_array(bitsize+1, params);
    t3 = Clock::now();
    Function_g(enc_y, enc_b, enc_r0, enc_r1, bitsize, cloud_key);
    t4 = Clock::now();
    cout << "Function g: "
         << chrono::duration_cast<chrono::seconds>(t4 - t3).count()
         << " seconds" << endl;

    // Decryption of enc_y to y
    uint64_t y = 0;
    for (int m = 0; m < bitsize; ++m) {
        uint8_t dec_mu = bootsSymDecrypt(&enc_y[m], key);
        y |= (dec_mu<<m);
    }

    // Comparison
    cout << "The decrypted random number is " << y << " but r0 and r1 are " << r0 << " and " << r1 << endl;
    if (y == r1)
        cout << "Client " << (int) client.getId() << " successfully authenticated to the server!" << endl;
    else
        cout << "Client " << (int) client.getId() << " could not authenticate to the server!" << endl;

    t2 = Clock::now();
    cout << "Protocol P: "
         << chrono::duration_cast<chrono::seconds>(t2 - t1).count()
         << " seconds" << endl;

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(max_bitsize, tmp);
    delete_gate_bootstrapping_ciphertext_array(max_bitsize, tmp_dist);
    delete_gate_bootstrapping_ciphertext_array(max_bitsize, enc_bound_match);
    delete_gate_bootstrapping_ciphertext_array(max_bitsize, enc_b);
    delete_gate_bootstrapping_ciphertext_array(bitsize, enc_r0);
    delete_gate_bootstrapping_ciphertext_array(bitsize, enc_r1);
    delete_gate_bootstrapping_ciphertext_array(bitsize+1, enc_y);
    delete_gate_bootstrapping_secret_keyset(key);
    //delete_gate_bootstrapping_cloud_keyset(cloud_key);
    delete_gate_bootstrapping_parameters(params);
    for (int i = 0; i < nslots; ++i) {
        delete_gate_bootstrapping_ciphertext_array(bitsize, enc_template_client[i]);
        delete_gate_bootstrapping_ciphertext_array(bitsize, enc_sample_client_true[i]);
        delete_gate_bootstrapping_ciphertext_array(bitsize, enc_sample_client_false[i]);
    }
    return 0;
}