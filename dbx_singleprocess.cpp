#include <iostream>
#include <vector>
#include <stdint.h>
#include <utility>
#include <algorithm>
#include <fstream>
#include <pthread.h>
#include <openssl/evp.h>



const std::string DROPBOX_PATH = "/mnt/d/bi0sctf/chall4/dropbox/instance1/";
std::vector<uint8_t> CLIENT_VEC = {'C', 'l', 'i', 'e', 'n', 't'};
const std::vector<uint8_t> IV = {108,7,56,1,52,36,115,88,3,255,114,105,51,19,97,81};
    
#define NUM_THREADS 10
typedef struct thread_data{
    uint64_t start;
    uint64_t end;
    uint8_t version;
    std::vector<uint8_t> raw_payload;
} tdata;

std::pair<uint8_t, std::vector<uint8_t>> unpack_payload(std::vector<uint8_t> data){
    uint8_t res1 = data[0];
    std::vector<uint8_t> res2;
    res2.assign(data.begin() + 1, data.end() - 16);
    return std::make_pair(res1, res2);
}

std::vector<uint8_t> read_file(std::string filename){
    std::vector<uint8_t> data;
    std::ifstream file(filename, std::ios::binary);
    file.seekg(0, std::ios::end);
    data.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read((char *)data.data(), data.size());
    file.close();
    return data;
}

unsigned char* calculate_md5(uint64_t inode_no){
    std::string str_inode = std::to_string(inode_no);
    std::string value = "ia9" + str_inode + "Xa|ui20";
    EVP_MD_CTX *mdctx;
    unsigned char *md5_digest;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
    
    // MD5_Init
    mdctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(mdctx);
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    // MD5_Update
    EVP_DigestUpdate(mdctx, (unsigned char*)value.c_str(), value.length());

    // MD5_Final
    md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);
    return md5_digest;
}

std::vector<uint8_t> decrypt_the_payload(std::vector<uint8_t> data, uint64_t inode_no){
    std::vector<uint8_t> output;
    output.resize(data.size());
    int outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    unsigned char* enc_key = calculate_md5(inode_no);
    std::vector<uint8_t> target_message = data;
    int inlen = target_message.size();
    EVP_DecryptInit(ctx, EVP_aes_128_cbc(), enc_key, IV.data());
    EVP_DecryptUpdate(ctx, output.data(), &outlen, target_message.data(), inlen);
    EVP_DecryptFinal(ctx, output.data()+outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return output;
}

// bool check(std::vector<uint8_t> first, std::vector<uint8_t> second){
//     std::sort(first.begin(), first.end());
//     std::cout << "\nRHA: contains:\n";
//     for(int i=0; i<first.size(); i++){
//         printf("%x ", first[i]);
//     }
//     printf("\n\n");
//     for(int i=0; i<second.size(); i++){
//         printf("%x ", second[i]);
//     }
//     printf("\n\n");
//     return std::includes(first.begin(), first.end(), second.begin(), second.end());
// }

bool check(std::vector<uint8_t> data) {
   for(int i=0; i<CLIENT_VEC.size();i++){
        if(data[i+2] != CLIENT_VEC[i])
            return false;
   }
   return true;
}


int get_versioned_key(tdata *td){
    std::vector<uint8_t> raw_payload = td->raw_payload; 
    uint64_t start = td->start;
    uint64_t end = td->end;
    
    std::vector<uint8_t> dec_payload;
    for(uint64_t inode_no=start; inode_no<=end; inode_no++){
        dec_payload = decrypt_the_payload(raw_payload, inode_no);
        bool result = check(dec_payload);
        if(result == true){
            std::cout << "\n ========================================== \n";
            std::cout << "[+] Key Found !\n";
            std::cout << "[*] Wanted Number: " << inode_no << "\n\n" << std::endl;
            // printf("result: %d\n", result);
            // for(int i=0;i <CLIENT_VEC.size(); i++){
            //     printf("%c", CLIENT_VEC[i]);
            // }
            exit(0);
        }
    }
    return 0;
}


int main(int argc, char *argv[]){

    if (argc < 3){
        std::cout << "[!] Usage: " << argv[0] << " <start> <end>" << std::endl;
        exit(0);
    }

    uint64_t start = atoll(argv[1]);
    uint64_t end = atoll(argv[2]);

    std::cout << "[*] Range Start: " << start << std::endl;
    std::cout << "[*] Range End: " << end << std::endl;
    
    std::string filename = DROPBOX_PATH + "hostkeys";
    
    std::cout << "[*] Reading file: " << filename << std::endl;
    std::vector<uint8_t> data = read_file(filename);
    std::pair<uint8_t, std::vector<uint8_t>> res = unpack_payload(data);

    tdata td;
    td.version = res.first;
    td.raw_payload = res.second;
    td.start = start;
    td.end = end;

    printf("[*] Version: %d\n", res.first);
    std::cout << "[*] Raw Payload len: " << res.second.size() << std::endl;


    // std::sort(CLIENT_VEC.begin(), CLIENT_VEC.end());
    int flag = get_versioned_key(&td);
    if(flag == 0){
        std::cout << "[!] Not Found\n\n" << std::endl;
    }
    return 0;
}