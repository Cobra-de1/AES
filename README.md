# C++ AES implementation

## 1. Using CryptoPP
+) Plaintext: 

    - Input from screen
    
    - Support Vietnamse (UTF-16)
+) Mode of operations:

    - Select mode from screen (using switch case)
  
    - Support modes:  ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM

+) Choose key length, iv length

+) Secret key and Initialization Vector (IV)

    select from screen (using switch case)

    Case 1: Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool

    Case 2: Input Secret Key and IV from screen

    Case 3: Input Secret Key and IV from file

+) OS platform

    - Code can compile on both Windows and Linux
    
 [Performance](Performance.md)

## 2. Using standand c++ library

+) Plaintext: 

    - Input from screen

    - Support Vietnamese (UTF-16)

+) Mode of operations

    - Using CBC mode

+) Secret key and Initialization Vector (IV)

    - Input Secret Key and IV from screen

+) OS platform

    - Code can compile on both Windows and Linux
