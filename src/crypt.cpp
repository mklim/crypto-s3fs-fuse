#include <stdio.h>
#include <sstream>
#include <string>
#include <iostream>
#include "crypt.h"
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
using namespace std;

int s3fs_encrypt(int fd, byte *key)
{
  //randomly generate iv
  CryptoPP::AutoSeededRandomPool prng;
  byte iv[CryptoPP::AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));
  string rawiv(reinterpret_cast<char*>(iv), CryptoPP::AES::BLOCKSIZE), striv;
  CryptoPP::StringSource s2(rawiv, true,
    new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(striv)
    )
  );

  //read file into char array
  int flength = lseek(fd, 0, SEEK_END);
  unsigned char* fcontents;
  fcontents = (unsigned char*) calloc(flength, sizeof(char));
  pread(fd, fcontents, flength, 0);
  string plain(reinterpret_cast<char*>(fcontents), flength);

  //encrypt plaintext into ciphertext
  string cipher;
  CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
  e.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
  CryptoPP::StringSource ss(plain, true,
    new CryptoPP::StreamTransformationFilter(e,
      new CryptoPP::HexEncoder(
        new CryptoPP::StringSink(cipher)
      )
    )
  );

  //write iv and encrypted data to file
  string output = striv+cipher;
  const char *buf = output.c_str();
  pwrite(fd, buf, output.length(), 0);
  ftruncate(fd, output.length());

  return 0;
}


int s3fs_decrypt(int fd, byte *key)
{
  // put entire file into string and decode hex
  int flength = lseek(fd, 0, SEEK_END);
  unsigned char* fcontents;
  fcontents = (unsigned char*) calloc(flength, sizeof(char));
  pread(fd, fcontents, flength, 0);
  string fraw(reinterpret_cast<char*>(fcontents), flength), fstr;
  CryptoPP::StringSource s3(fraw, true,
    new CryptoPP::HexDecoder(
      new CryptoPP::StringSink(fstr)
    )
  );
  if(fstr.length() < 16)
    return 1;

  // pull iv and cipher from decoded hex
  byte iv[CryptoPP::AES::BLOCKSIZE];
  strncpy((char*)iv, fstr.c_str(), CryptoPP::AES::BLOCKSIZE);
  string cipher = fstr.substr(CryptoPP::AES::BLOCKSIZE, fstr.length()-CryptoPP::AES::BLOCKSIZE), ciph2;

  //decrypt, with the cipher as your base
  string recovered;
  try
  {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
    CryptoPP::StringSource ss(cipher, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(recovered)
      )
    );  
  }
  catch(const CryptoPP::Exception& e)
  {
    cout << "error decrypting file";
    recovered = fraw;
  }

  //write recovered text to file
  pwrite(fd, recovered.c_str(), recovered.length(), 0);
  ftruncate(fd, recovered.length());

  return 0;
}


int s3fs_keyform(byte* outkey, string inkey)
{
  CryptoPP::HexEncoder encoder;
  encoder.Put((byte*)inkey.c_str(), inkey.length());
  encoder.MessageEnd();
  encoder.Get(outkey, CryptoPP::AES::DEFAULT_KEYLENGTH);
  return 0; 
}
