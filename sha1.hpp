/*
 sha1.hpp - header of
 ============
 SHA-1 in C++
 ============
 100% Public Domain.
 Original C Code
 -- Steve Reid <steve@edmweb.com>
 Small changes to fit into bglibs
 -- Bruce Guenter <bruce@untroubled.org>
 Translation to simpler C++ Code
 -- Volker Grabsch <vog@notjusthosting.com>
 Safety fixes
 -- Eugene Hopkinson <slowriot at voxelstorm dot com>
 Modified SHA1 to allow mac extension attack
 -- Zach Brogan <zachbrogan@gmail.com>
 */


#ifndef sha1_hpp
#define sha1_hpp

#include <stdio.h>
#include <cstdint>
#include <iostream>
#include <string>


class SHA1
{
public:
    SHA1();
    void setInitialHash(std::string initial_hash);
    void update(const std::string &s);
    void update(std::istream &is);
    std::string final();
    std::string final(uint64_t total_bits);
    static std::string from_file(const std::string &filename);
    std::string macExtensionMessage(std::string original_message, int key_size, std::string new_message);
    std::string macExtensionMac(std::string original_mac, int key_size, std::string new_message, std::string spoofed_message);
    
private:
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms;
};

#endif /* sha1_hpp */







