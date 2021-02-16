//
// Created by gaetan on 01/07/2020.
//

#ifndef TFHE_PROTOCOL_CLIENT_H
#define TFHE_PROTOCOL_CLIENT_H

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>


/* Class of a Client on Server side, thus has less information that the Client on Client side, only encrypted data.
 * Where shall be this Class? In Server.h ?*/
class Client{
        private:
        /*Parameters */
        unsigned short int ID; // The unique IDentifier of a Client
        const TFheGateBootstrappingSecretKeySet* key;  //The secret key associated with the Client with the particular ID
        const std::vector<LweSample*> ctxt; // The biometric data encrypted.
        const int nb_slots;
        public:

    Client(unsigned short id, const TFheGateBootstrappingSecretKeySet *key, const std::vector<LweSample *> &ctxt,
           const int nbSlots) : ID(id), key(key), ctxt(ctxt), nb_slots(nbSlots) {}


    ~Client() {}

    unsigned short getId() const {
        return ID;
    }

    void setId(unsigned short id) {
        ID = id;
    }

    const TFheGateBootstrappingSecretKeySet *getKey() const {
        return key;
    }

    void setKey(const TFheGateBootstrappingSecretKeySet *key) {
        Client::key = key;
    }

    const std::vector<LweSample *> &getCtxt() const {
        return ctxt;
    }

    const int getNbSlots() const {
        return nb_slots;
    }
};

/* Class of a Client on Client side, i.e. that any biometric data is encrypted at this point.*/
class Client_C: public Client {
private:
    /* Parameters
    The commented parameters are already in the class Client on Server side.
    The inheritance is implemented currently. Thus this class has all these parameters.
    Working correctly for now.
     */
//    unsigned short int ID; //The unique IDentifier of a Client
    const int minimum_lambda = 80;
    const TFheGateBootstrappingParameterSet *params; //The params, public, important for ?? homomorphic operation, in particular generating keys and bootstrapping.
    const TFheGateBootstrappingCloudKeySet *cloud_key;
    std::vector<uint8_t> ptxt; // The plaintext of the biometric data. For now format from std. Can be changed.
//    const TFheGateBootstrappingSecretKeySet* key;  // The secret key associated with the Client with the particular ID
//    const LweSample* ctxt; // The biometric data encrypted.
public:

    Client_C(unsigned short id, const TFheGateBootstrappingSecretKeySet *key, const std::vector<LweSample*> &ctxt,
             const int nbSlots, const int minimumLambda, const TFheGateBootstrappingParameterSet *params,
             const TFheGateBootstrappingCloudKeySet *cloudKey, std::vector<uint8_t> ptxt) : Client(id, key, ctxt, nbSlots),
                                                                               minimum_lambda(minimumLambda),
                                                                               params(params), cloud_key(cloudKey),
                                                                               ptxt(ptxt) {}

    virtual ~Client_C() {

    }

    const int getMinimumLambda() const {
        return minimum_lambda;
    }

    const TFheGateBootstrappingParameterSet *getParams() const {
        return params;
    }

    void setParams(const TFheGateBootstrappingParameterSet *params) {
        Client_C::params = params;
    }

    const TFheGateBootstrappingCloudKeySet *getCloudKey() const {
        return cloud_key;
    }

    void setCloudKey(const TFheGateBootstrappingCloudKeySet *cloudKey) {
        cloud_key = cloudKey;
    }

    const std::vector<uint8_t> &getPtxt() const {
        return ptxt;
    }

    void setPtxt(const std::vector<uint8_t> &ptxt) {
        Client_C::ptxt = ptxt;
    }

};

void printVector(std::vector<uint8_t> v, long size);
void printVect64(std::vector<uint64_t> v, uint64_t length);


#endif //TFHE_PROTOCOL_CLIENT_H
