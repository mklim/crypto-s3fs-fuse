#ifndef S3FS_CRYPT_H_
#define S3FS_CRYPT_H_

/*
 * A collection of functions handling encryption/decryption of any given set of files.
 */

#include <stdio.h>
#include <string>
#include "cryptopp/modes.h"


int s3fs_decrypt(int fd, byte *key);
int s3fs_encrypt(int fd, byte *key);
int s3fs_keyform(byte* outkey, std::string inkey);

#endif // S3FS_CRYPT_H_