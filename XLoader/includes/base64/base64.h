#include <string>

std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(unsigned char* encoded_string, int in_len);
