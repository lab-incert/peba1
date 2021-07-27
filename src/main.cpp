//
// Created by gpr on 16/07/2021.
//

#include <iostream>
#include <chrono>
#include "../include/Client.h"
#include "../include/Math.h"

using namespace std;

typedef chrono::high_resolution_clock Clock;

int main(void)
{
    /*
     * Initialisation for the client
     */
    unsigned short int ID = 007; //The unique IDentifier of a Client

    /*
     * Initialisation for the homomorphic encryption
     */
    const int minimum_lambda = 128;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda); //The params, public, important for ?? homomorphic operation, in particular generating keys and bootstrapping.
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);  //The secret key associated with the Client with the particular ID
    const TFheGateBootstrappingCloudKeySet* cloud_key = &key->cloud;

    /*
     * Testing phase
     */
    // Create 3 vectors of long with nslots elements for test
//    cout << "Creation of the test vectors" << endl;
    static const uint32_t nslots = 128;
    static const uint32_t bitsize = 8; //8 significant bits, however a sign bit will be used
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
        if (i%2==0)
        {
//            srand(time(NULL)*i^3);
//            template_client[i] =  rand() %256;
            sample_client_true[i] = template_client[i] + 1;
            srand(time(NULL)+i);
            sample_client_false[i] = i;//rand() %256;
            template_client[i] = 94;
//            sample_client_false[i] = 173;
        }
        else
        {
            srand(time(NULL)*i^3);
            template_client[i] = - rand() %256;
            sample_client_true[i] = -(template_client[i] + 1);
            srand(time(NULL)+i);
            sample_client_false[i] = -i-2;//rand() %256;
            template_client[i] = 216;
//            sample_client_false[i] = 173;
        }
//        template_client[i] = 14;
//        sample_client_true[i] = -(template_client[i] + 1);
//        sample_client_false[i] = 50;
    }

    cout << "template_client" << endl;
    printVector(template_client, nslots);
    cout << "sample_client_true" << endl;
    printVector(sample_client_true, nslots);
    cout << "sample_client_false" << endl;
    printVector(sample_client_false, nslots);

    // Test of correctness of encryption and decryption
    cout << "Test of correctness of encryption/decryption\n" << endl;
//    cout << "Creation of the encrypted test vectors" << endl;
    vector<LweSample*> enc_template_client(nslots);
    vector<LweSample*> enc_sample_client_true(nslots);
    vector<LweSample*> enc_sample_client_false(nslots);

    // Encryption
    for (int i = 0; i < nslots; i++) {
        enc_template_client[i] = new_gate_bootstrapping_ciphertext_array(bitsize, params);
        enc_sample_client_true[i] = new_gate_bootstrapping_ciphertext_array(bitsize, params);
        enc_sample_client_false[i] = new_gate_bootstrapping_ciphertext_array(bitsize, params);
        for (int j=0; j < bitsize; j++) {
            uint8_t mu = template_client[i];
            bootsSymEncrypt(&enc_template_client[i][j], (mu>>j)&1, key);
            mu = sample_client_true[i];
            bootsSymEncrypt(&enc_sample_client_true[i][j], (mu>>j)&1, key);
            mu = sample_client_false[i];
            bootsSymEncrypt(&enc_sample_client_false[i][j], (mu>>j)&1, key);
        }
    }

    // Decryption
//    cout << "Encryption done\nNow let's start decryption" << endl;
    vector<uint8_t>  dec_template_client(nslots);
    vector<uint8_t>  dec_sample_client_true(nslots);
    vector<uint8_t>  dec_sample_client_false(nslots);
    for (int i = 0; i < nslots; i++) {
        for (int j = 0; j < bitsize; j++) {
            uint8_t dec_mu = bootsSymDecrypt(&enc_template_client[i][j], key);
            dec_template_client[i] |= (dec_mu<<j);
            dec_mu = bootsSymDecrypt(&enc_sample_client_true[i][j], key);
            dec_sample_client_true[i] |= (dec_mu<<j);
            dec_mu = bootsSymDecrypt(&enc_sample_client_false[i][j], key);
            dec_sample_client_false[i] |= (dec_mu<<j);
        }
    }

//    cout << "Decryption done\nLet's print the vectors" << endl;
//    printVector(dec_template_client, nslots);
//    cout << "template_client" << endl;
//    printVector(dec_sample_client_true, nslots);
//    cout << "sample_client_true" << endl;
//    printVector(dec_sample_client_false, nslots);
//    cout << "sample_client_false" << endl;

    if (template_client == dec_template_client && sample_client_true == dec_sample_client_true && sample_client_false == dec_sample_client_false)
    {
        cout << "Correctness succeeds.\n" << endl;
    }
    else
    {
        cout << "Correctness fails.\n" << endl;
        return EXIT_FAILURE;
    }



    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(max_bitsize, params);
    uint64_t tmp_result = 0;
    auto t_from = Clock::now();
    auto t_to = Clock::now();
    chrono::duration<double> t_average;
    int loop = 64; //number of operations

// ------------------------------------------------------
//   BEGINNING OF THE SUITE OF TESTS ON THE PLAINTEXT DOMAIN
// ------------------------------------------------------
    cout << "The tests on the plaintext domain will now proceed." << endl;
    /*
     * New vectors are initialised and each value is coded on  bits, in order to ensure correctness of the operations.
     */
    int bitsize64 = 64;
    vector<uint64_t> test(nslots);
    vector<uint64_t> test2(nslots);
    for (int i = 0; i < nslots; ++i) {
            test[i] = template_client[i];
            test2[i] = sample_client_false[i];
    }

//    cout << "test vector" << endl;
//    printVect64(test, nslots);
//    cout << "test2 vector" << endl;
//    printVect64(test2, nslots);

// Addition bitwise

    int cnt = 0;

    uint64_t res;
    t_average = t_to - t_to;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        srand(time(NULL)*i+1);
        int r2 = rand() %nslots;
        t_from = Clock::now();
        res = ADDNbit(test[r1], test2[i], bitsize64);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Addition n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t_to - t_from).count() << " nanoseconds" << endl;
        if (res == (test[r1] + test2[i]))
        {
            cnt++;
        }
    }
    cout << "Addition: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Addition average time: " << chrono::duration_cast<chrono::nanoseconds>(t_average).count()/loop << " nanoseconds" << endl;


    // Two's complement
    cnt = 0;
    t_average = t_to - t_to;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        t_from = Clock::now();
        res = TwoSComplement(test2[i], 64);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Two's complement: " << chrono::duration_cast<chrono::nanoseconds>(t_to - t_from).count() << " nanoseconds" << endl;
        if (res == -test2[i])
        {
            cnt++;
        }
    }
    cout << "Two's complement: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Two's complement average time: " << chrono::duration_cast<chrono::nanoseconds>(t_average).count()/loop << " nanoseconds" << endl;

    // Absolute value
    cnt =0;
    t_average = t_to - t_to;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        t_from = Clock::now();
        res = ABS(test2[i], bitsize64);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Absolute n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t_to - t_from).count() << " nanoseconds" << endl;
        if (res == test2[i])
        {
            cnt++;
        }
    }
    cout << "Absolute value: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Absolute value average time: " << chrono::duration_cast<chrono::nanoseconds>(t_average).count()/loop << " nanoseconds" << endl;

    // Subtraction n bits
    cnt = 0;
    t_average = t_to - t_to;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        srand(time(NULL)*i+1);
        int r2 = rand() %nslots;
        t_from = Clock::now();
        res = SUBNbit(test[r1], test2[i], bitsize64);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Subtraction n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t_to - t_from).count() << " nanoseconds" << endl;
        uint64_t tmp_res = ABS(test[r1] - test2[i], bitsize64);
        if (res == tmp_res)
        {
            cnt++;
        }
    }
    cout << "Subtraction: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Subtraction average time: " << chrono::duration_cast<chrono::nanoseconds>(t_average).count()/loop << " nanoseconds" << endl;

    // Multiplication of two n-bit numbers
    cnt=0;
    t_average = t_to - t_to;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL)*i^3);
        int r1 = rand() %nslots;
        srand(time(NULL)*i+1);
        int r2 = rand() %nslots;
        t_from = Clock::now();
        res = Multiply(test[r1], test2[i], bitsize);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Multiplication n-bit: " << chrono::duration_cast<chrono::nanoseconds>(t_to - t_from).count() << " nanoseconds" << endl;
        if (res == test[r1]*test2[i])
        {
            cnt++;
        }
    }
    cout << "Multiplication: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Multiplication average time: " << chrono::duration_cast<chrono::nanoseconds>(t_average).count()/loop << " nanoseconds" << endl;

    // Manhattan distance of two vectors
    cnt=0;
    cout << "Test of the Manhattan distance" << endl;
    t_from = Clock::now();
    res = ManhattanDistanceBitwise(test, test2, bitsize64);
    t_to = Clock::now();
    cout << "Manhattan distance bitwise: " << chrono::duration_cast<chrono::nanoseconds>(t_to - t_from).count() << " nanoseconds" << endl;
//    cout << "The result is ";
//    printSlot64(res);
//    cout << " and should be ";
    tmp_result = ManhattanDistance(template_client, sample_client_false);
//    printSlot64(tmp_result);
//    cout << endl;
    if (res == tmp_result)
        cnt++;
    cout << "Manhattan distance bitwise: " << cnt << " success, " << 1-cnt << " fails" << endl;


    // Euclidean distance of two vectors
    cnt=0;
    cout << "Test of the euclidean distance" << endl;
    t_from = Clock::now();
    res = EuclideanDistanceBitwise(test, test2, bitsize64);
    t_to = Clock::now();
    cout << "Euclidean distance bitwise: " << chrono::duration_cast<chrono::nanoseconds>(t_to - t_from).count() << " nanoseconds" << endl;
//    cout << "The result is ";
//    printSlot64(res);
//    cout << " and should be ";
    tmp_result = EuclideanDistance(template_client, sample_client_false);
//    printSlot64(tmp_result);
//    cout << endl;
    if (res == tmp_result)
        cnt++;
    cout << "Euclidean distance bitwise: " << cnt << " success, " << 1-cnt << " fails" << endl;

    /*
    * The final test of the protocol
    */
    cout << "\n------------------------\nThe protocol THREATS is tested on the plaintext domain!" << endl;
    uint64_t bound_match_clear = 10000000; // arbitrary choice
    t_from = Clock::now();
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
    t_to = Clock::now();
    cout << "Protocol P bitwise: " << chrono::duration_cast<chrono::microseconds>(t_to - t_from).count() << " microseconds" << endl;

// ------------------------------------------------------
//   BEGINNING OF THE SUITE OF TESTS ON THE CIPHERTEXT DOMAIN
// ------------------------------------------------------

     cout << "--------------------------------------\nBeginning of the tests on the ciphertext domain" << endl;
    // Addition
    cnt = 0;
    t_average = t_to - t_to;
    for (int i = 0; i < 0; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2+1);
        int r2 = rand() %nslots;
        for (int i = 0; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }
        cout << "Test of the addition of 2 n-bit numbers " << (int) template_client[r1] << " + "
             << (int) sample_client_false[r2] << endl;
        t_from = Clock::now();
        bootsADDNbit(tmp, enc_template_client[r1], enc_sample_client_false[r2], bitsize, cloud_key);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Addition n-bit: "
//             << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
//             << " seconds" << endl;
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
//        printf("The result is %ld and should be %d\n", tmp_result, sample_client_true[r1] + template_client[r2]);
        if (tmp_result == (template_client[r1] + sample_client_false[r2]))
        {
            cnt++;
            printf("The result is %ld\n", tmp_result);
        }
        else
            printf("The result is %ld and should be %d\n", tmp_result, sample_client_true[r1] + template_client[r2]);
    }
    cout << "Addition: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Addition average time: " << chrono::duration_cast<chrono::seconds>(t_average).count()/loop << " seconds" << endl;


    // Two's complement
    cnt=0;
    t_average = t_to - t_to;
    for (int i = 0; i < 0; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;;
        for (int i = 0; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }
        cout << "Test of the two's complement of a n-bit numbers " << (int) sample_client_false[i] << endl;
        t_from = Clock::now();
        bootsTwoSComplement(tmp, enc_sample_client_false[i], bitsize, cloud_key);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Two's complement n-bit: "
//             << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
//             << " seconds" << endl;
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        if ( ((sample_client_false[i] == 0) && (tmp_result == 0)) || ( tmp_result == (256-sample_client_false[i])) )
        {
            cnt++;
//            printf("The result is %ld\n", tmp_result);
            printf("The result is %ld\n", tmp_result);
        }
        else
            printf("The result is %ld and should be %d\n", tmp_result, 256-sample_client_false[i]);
    }
    cout << "Two's complement: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Two's complement average time: " << chrono::duration_cast<chrono::seconds>(t_average).count()/loop << " seconds" << endl;

    // Absolute value
    cnt =0;
    t_average = t_to - t_to;
    for (int i = 0; i < 0; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        for (int i = 0; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }
        cout << "Test of the absolute value of a n-bit numbers " << (int) sample_client_false[i] << endl;
        t_from = Clock::now();
        bootsABS(tmp, enc_sample_client_false[i], bitsize, cloud_key);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Absolute n-bit: "
//             << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
//             << " seconds" << endl;
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        if ( ((sample_client_false[i] < 128) && (tmp_result == sample_client_false[i])) || ((sample_client_false[i] >= 128) && (tmp_result == -(sample_client_false[i]-256))))
        {
            cnt++;
        }
        else
        {
            if (sample_client_false[i] < 128)
                printf("The result is %ld and should be %d\n", tmp_result, sample_client_false[i]);
            else
                printf("The result is %ld and should be %d\n", tmp_result, sample_client_false[i]-128);
        }

    }
    cout << "Absolute value: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Absolute value average time: " << chrono::duration_cast<chrono::seconds>(t_average).count()/loop << " seconds" << endl;

    // Subtraction
    cnt=0;
    t_average = t_to - t_to;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2);
        int r2 = rand() %nslots;

        for (int i = 0; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }
        cout << "Test of the subtraction of two n-bit numbers " << (int) template_client[r1] << " - "
             << (int) sample_client_false[r2] << endl;
        t_from = Clock::now();
        bootsSUBNbit(tmp, enc_template_client[r1], enc_sample_client_false[r2], bitsize, cloud_key);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
        cout << "Subtraction n-bit: "
             << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
             << " seconds" << endl;
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        if (tmp_result == abs(template_client[r1] - sample_client_false[r2]))
        {
            cnt++;
            printf("The result is %lu and should be |%d|\n", tmp_result, template_client[r1] - sample_client_false[r2]);
        }
        else
            printf("The result is %lu and should be |%d|\n", tmp_result, template_client[r1] - sample_client_false[r2]);
    }
    cout << "Subtraction: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Subtraction average time: " << chrono::duration_cast<chrono::seconds>(t_average).count()/loop << " seconds" << endl;

    // Multiplication
    cnt=0;
    t_average = t_to - t_to;
    for (int i = 0; i < loop; ++i) {
        srand(time(NULL));
        int r1 = rand() %nslots;
        srand(time(NULL)*2);
        int r2 = rand() %nslots;

        for (int i = 0; i < max_bitsize; ++i) {
            bootsCONSTANT(&tmp[i], 0, cloud_key);
        }
        cout << "Test of the multiplication of two n-bit numbers " << (int) template_client[r1] << " x "
             << (int) sample_client_false[r2] << endl;
        t_from = Clock::now();
        bootsMultiply(tmp, enc_template_client[r1], enc_sample_client_false[r2], bitsize, cloud_key);
        t_to = Clock::now();
        chrono::duration<double> t_duration = t_to - t_from;
        t_average += t_duration;
//        cout << "Multiplication n-bit: "
//             << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
//             << " seconds" << endl;
        tmp_result = 0;
        for (int m = 0; m < max_bitsize; ++m) {
            uint8_t dec_mu = bootsSymDecrypt(&tmp[m], key);
            tmp_result |= (dec_mu << m);
        }
        if (tmp_result == (template_client[r1] * sample_client_false[r2]))
        {
            cnt++;
        }
        else
            printf("The result is %lu and should be %d\n", tmp_result, template_client[r1] * sample_client_false[r2]);
    }
    cout << "Multiplication: " << cnt << " success, " << loop-cnt << " fails" << endl;
    cout << "Multiplication average time: " << chrono::duration_cast<chrono::seconds>(t_average).count()/loop << " seconds" << endl;

    /*
    * Test of distance
    */
    cout << "Now we test the distances" << endl;
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
    cout << "The result shall be as follows: mh est " << mh << " et eh est " << eh << endl;
    for (int i = 0; i < max_bitsize; ++i) {
        bootsCONSTANT(&tmp_dist[i], 0, cloud_key);
    }
    t_from = Clock::now();
    HE_ManhattanDistance(tmp_dist, enc_template_client, enc_sample_client_true, bitsize, cloud_key);
    t_to = Clock::now();
    cout << "Manhattan distance: "
         << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
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
    t_from = Clock::now();
    HE_EuclideanDistance(tmp_dist, enc_template_client, enc_sample_client_true, bitsize, cloud_key);
    t_to = Clock::now();
    cout << "Euclidean distance: "
         << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
         << " seconds" << endl;
    for (int m = 0; m < max_bitsize; ++m) {
        uint8_t dec_mu = bootsSymDecrypt(&tmp_dist[m], key);
        tmp_result |= (dec_mu<<m);
    }
    printf("The result for Euclidean distance is %lu and should be %lu\n", tmp_result, eh);


    /*
     * The final test of the protocol THREATS
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

    t_from = Clock::now();


    Client_C client(ID, key, enc_sample_client_true, nslots, minimum_lambda, params ,cloud_key, sample_client_true);

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

    t_to = Clock::now();
    cout << "Protocol P: "
         << chrono::duration_cast<chrono::seconds>(t_to - t_from).count()
         << " seconds" << endl;


    /*
     * Cleaning part
     */
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