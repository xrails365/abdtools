#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <wincrypt.h>
#include <limits>
#include <stdlib.h>
#include <iostream>
#pragma comment (lib, "crypt32.lib")

bool DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        //printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return false;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        //printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return false;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        //printf("Failed in CryptHashData (%u)\n", GetLastError());
        return false;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        //printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return false;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        //printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return false;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return true;
}

std::string base64Decode(const std::string& encodedString) {
    const std::string base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string decodedString;
    int val = 0, valb = -8;
    for (char c : encodedString) {
        if (c == '=') {
            break;
        }
        if (c >= 'A' && c <= 'Z') {
            c -= 'A';
        }
        else if (c >= 'a' && c <= 'z') {
            c -= 'a' - 26;
        }
        else if (c >= '0' && c <= '9') {
            c -= '0' - 52;
        }
        else if (c == '+') {
            c = 62;
        }
        else if (c == '/') {
            c = 63;
        }
        else {
            continue;
        }

        val = (val << 6) + c;
        valb += 6;
        if (valb >= 0) {
            decodedString.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decodedString;
}

int main(int argc, char* argv[]) {

    std::string base64str = "AAAAAAAAAAAAAAAAAAAAAOT1+2rub097kSyq7vGTf6E=";
    std::string str = base64Decode(base64str); 
    //std::cout << str;
    
    if(DecryptAES((char*)str.c_str(), str.length(), (char*)"your_key_here", 13)) {
        std::cout << str;
    }
}
