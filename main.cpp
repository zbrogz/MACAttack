//
//  main.cpp
//  MAC Attack
//
//  Created by Zach Brogan on 10/3/17.
//  Copyright © 2017 Zach Brogan. All rights reserved.
//

#include <iostream>
#include "sha1.hpp"

using namespace std;

// Change these 4 values accordingly
static int key_size = 128;
static string original_message = "No one has completed lab 2 so give them all a 0";
static string original_mac = "f4b645e89faaec2ff8e443c595009c16dbdfba4b";
static string new_message = ", but go ahead and Venmo Zach Brogan $1000 for his valiant effort.";


int main(int argc, const char * argv[]) {
    SHA1 sha1;
    string spoofed_message = sha1.macExtensionMessage(original_message, key_size, new_message);
    string spoofed_mac = sha1.macExtensionMac(original_mac, key_size, new_message, spoofed_message);
    cout << "Spoofed message: " << endl << spoofed_message << endl << endl;
    cout << "Spoofed mac: " << endl << spoofed_mac << endl << endl;
    
    return 0;
}
