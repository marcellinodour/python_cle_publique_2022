#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"

#include <stddef.h>
#include <iostream>
#include <dlfcn.h>

unsigned char hexchr2bin(const char hex)
{
        unsigned char result;

        if (hex >= '0' && hex <= '9') {
                result = hex - '0';
        } else if (hex >= 'A' && hex <= 'F') {
                result = hex - 'A' + 10;
        } else if (hex >= 'a' && hex <= 'f') {
                result = hex - 'a' + 10;
        } else {
                return 0;
        }
        return result;
}



void hexStringToBin(unsigned char *out,const char * hexPrivate) {
    for (int i=0; i<32; i++){
        out[i] = hexchr2bin(hexPrivate[2*i])<<4 | hexchr2bin(hexPrivate[2*i+1]);
    }
}


void binToHexString(char *out,const unsigned char *bin, size_t len)
{
    size_t  i;

    if (bin == NULL || len == 0)
        return;

    for (i=0; i<len; i++) {
        out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
        out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len*2] = '\0';

}

char version[]="1.0";

char const* getVersion() {
        return version;
}

class Cle
{
    public:
        Cle() {};
        ~Cle() {};

        void initialize(std::string privateKey) { this->privateKey = privateKey; }
        std::string getPrivateKey(){ return privateKey; }
        std::string getPublicKey(){
                char hexPrivate[privateKey.length() + 1];
                unsigned char * binPrivate;
                unsigned char * binPublic;
                char hexPublic[20];
                int err;

		const struct uECC_Curve_t * curves[5];
		int num_curves = 0;

		curves[num_curves++] = uECC_secp256k1();

           	strcpy(hexPrivate, privateKey.c_str());
		std::cout << "private Key : " << hexPrivate << std::endl;

                hexStringToBin(binPrivate, hexPrivate);

               /* void* hndl = dlopen("micro-ecc/component_uECC.so", RTLD_LAZY);
		if(!hndl){
			std::cout<<"Error, trou de bal !";
		}
                int (*fct) (uint8_t*, uint8_t*, uECC_Curve_t);

                fct = (int (*) (uint8_t*, uint8_t*, uECC_Curve_t)) dlsym(hndl, "uECC_compute_public_key");

                if (!fct(binPrivate, binPublic, curves[5])) {
                        printf("uECC_compute_public_key() failed\n");
                }*/

		err = uECC_compute_public_key(binPrivate, binPublic, curves[0]);

                binToHexString(hexPublic, binPublic, privateKey.length());           
		std::cout << "public Key : " << hexPublic << std::endl;

                return hexPublic; }

    private:
        std::string privateKey;
};
 
namespace py = pybind11;


PYBIND11_MODULE(cle_component,greetings)
{
  greetings.doc() = "greeting_object 1.0";
  greetings.def("getVersion", &getVersion, "a function returning the version");
  
   // bindings to Cle class
    py::class_<Cle>(greetings, "Cle", py::dynamic_attr())
	.def(py::init<>())
        .def("initialize", &Cle::initialize)
        .def("getPrivateKey", &Cle::getPrivateKey)
        .def("getPublicKey", &Cle::getPublicKey);
}
