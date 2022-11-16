#include <algorithm>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <string>


using std::cout;
using std::cerr;
using std::endl;
using std::ios;
using std::ifstream;
using std::ofstream;
using std::string;

static ifstream in_file;
static ofstream out_file;


bool cmpBits(char data, int &shift) {
    return (data >> shift--) & 0x01;
}

uint32_t setReverse(uint32_t tmpInt) {
    uint32_t buffer = 0x00;
    for (int b = 0; b < 4; ++b) {
        buffer |= (tmpInt >> (0x00 + (8 * b))) & 0xFF;
        if (b != 3) buffer <<= 8;
    }
    return buffer;
}


//Rewrite of bnnm's LZGPRS thing
void DecryptGPRS(uint32_t &index, uint32_t dst_size) {
    //cout << "Decompressing" << endl;
    char *dst = new char[dst_size];
    //cout << "Created temporary array with size " << dst_size << endl;
    uint32_t dst_curr = 0;
    //cout << "Set dst_curr to 0" << endl;
    uint32_t dst_end = dst_curr + dst_size;
    //cout << "Set dst_end to " << dst_end << endl;
    uint32_t dst_next = dst_curr;
    //cout << "Set dst_next to " << dst_next << endl;
    uint32_t src_curr = index + 0x08;
    //cout << "Set src_curr to " << src_curr << endl;
    uint32_t src_next = src_curr + 0x01;
    //cout << "Set src_next to " << src_next << endl;

    int shift, addr;
    char buff, cur;

    in_file.seekg(src_curr++);
    //cout << "Seek to src_curr" << endl;
    in_file.get(cur);
    //cout << "Get to cur" << endl;
    //cout << "cur is " << (int(cur) & 0xFF) << endl;
    shift = 7;
    //cout << "Set shift to 7" << endl;
    do {
        //cout << "Main loop" << endl;
        while (true) {
            //cout << "First loop" << endl;
            if (shift < 0) {
                in_file.seekg(src_curr);
                in_file.get(cur);
                shift = 7;
                src_next = src_curr + 1;
            }
            else src_next = src_curr;

            if (cmpBits(cur, shift)) break;

            //cout << "First loop raw byte" << endl;
            in_file.seekg(src_next);
            in_file.get(buff);
            dst[dst_curr++] = buff;
            src_curr = src_next + 1;
        }
        //cout << "Break first loop" << endl;

        if (shift < 0) {
            in_file.seekg(src_next++);
            in_file.get(cur);
            shift = 7;
        }

        in_file.seekg(src_next);
        in_file.get(buff);

        if (!cmpBits(cur, shift)) {
            //cout << "Unset addr" << endl;
            src_curr = src_next + 1;

            if (!buff) break;

            addr = 0xFFFFFF00 | buff;
        }
        else {
            //cout << "Set addr" << endl;
            uint32_t src_temp = buff;
            uint8_t nib_temp = 0;

            src_curr = src_next + 1;

            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }
            nib_temp = cmpBits(cur, shift);

            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits(cur, shift);

            if (shift < 0) {
               in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits(cur, shift);

            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits(cur, shift);

            addr = (0xFFFFFF00 | src_temp);
            addr = (addr << 4) | nib_temp;
            addr -= 0xFF;
        }

        int count = 1;
        while (true) {
            //cout << "Count loop" << endl;
            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }

            if (!cmpBits(cur, shift)) break;

            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }

            //cout << "Count loop alter count" << endl;
            count = count * 2 + ((cmpBits(cur, shift)) ? 1 : 0);
        }

        if (count < 7) {
            //cout << "Count under 7 copied byte" << endl;
            count += 1;

            dst_next = dst_curr + addr;
            while (count--) {
                dst[dst_curr++] = dst[dst_next++];
            }
        }
        else {
            //cout << "Count 7+ copied byte" << endl;
            int add = ++count & 0x07;
            count = (count >> 3) + 1;

            dst_curr += (add - 8);
            dst_next = dst_curr + addr;
            while (true) {
                int a;

                if (!add) {
                    a = add;
                    dst_curr += 8;
                    dst_next += 8;
                    if (!(--count)) break;
                }
                else a = (~add & 0x07) + 1;

                for (; a < 8; ++a) {
                    dst[dst_curr + a] = dst[dst_next + a];
                }
                if (add) add = 0;
            }
        }
    } while (in_file.get(buff) && dst_curr < dst_end);
    //cout << "Stop decompressing" << endl;

    out_file.write((const char*)(dst), dst_end);
    //cout << "Copied decompressed to outfile" << endl;

    index = src_next;
}

void SkipGARC(uint32_t &index) {
    uint32_t cfileAddr;                                                         // 32 bit le, FILE chunk location
    uint32_t cnameAddr;                                                         // 32 bit le, NAME chunk location
    uint32_t cdataAddr;                                                         // 32 bit le, DATA chunk location
    uint32_t termAddr;                                                          // 32 bit le, TERM location

    uint32_t tempAddr = 0x14;

    in_file.seekg(index + tempAddr);
    in_file.read((char*)(&cfileAddr), sizeof(uint32_t));

    tempAddr = cfileAddr + 0x04;
    in_file.seekg(index + tempAddr);
    in_file.read((char*)(&cnameAddr), sizeof(uint32_t));

    tempAddr = cnameAddr + 0x04;
    in_file.seekg(index + tempAddr);
    in_file.read((char*)(&cdataAddr), sizeof(uint32_t));

    tempAddr = cdataAddr + 0x04;
    in_file.seekg(index + tempAddr);
    in_file.read((char*)(&termAddr), sizeof(uint32_t));

    in_file.seekg(index);
    for (int i = 0; i < (termAddr + 0x04); ++i) {
        char buff;
        in_file.get(buff);
        out_file.put(buff);
    }

    index += (termAddr + 0x04);
}

void searchGPRS(string filename) {
    const uint32_t GPRS = 0x47505253;
    const uint32_t GARC = 0x47415243;

    in_file.open(filename.c_str(), ios::in | ios::binary);
    if (!in_file.is_open()) {
        cerr << "Unable to read \"" << filename << "\"" << endl;
        return;
    }
    else cout << filename.substr(filename.find_last_of("\\/") + 1)
              << " opened for decompressing" << endl;

    char buff;
    int num_gprs = 0;
    uint32_t index = 0x00;
    uint32_t decomp_size;
    uint32_t chunk;

    out_file.open((filename + ".dec").c_str(), ios::out | ios::app | ios::binary);
    if (!out_file.is_open()) {
        cerr << "Unable to write to \"" << (filename + ".dec") << "\"" << endl;
        in_file.close();
        return;
    }
    else cout << filename.substr(filename.find_last_of("\\/") + 1) + ".dec"
              << " opened for writing" << endl;

    while (in_file.get(buff)) {
        in_file.seekg(index);
        in_file.read((char*)(&chunk), sizeof(uint32_t));

        if (setReverse(chunk) == GARC) SkipGARC(index);
        else if (setReverse(chunk) == GPRS) {
            num_gprs += 1;

            //Grabs size of decompressed section from GPRS header thing
            in_file.seekg(index + 0x04);
            in_file.read((char*)(&decomp_size), sizeof(uint32_t));
            decomp_size = setReverse(decomp_size);

            //cout << "Current index is " << index << endl;
            uint32_t index_curr = index;
            DecryptGPRS(index, decomp_size);
            cout << "Decompressed the section at offset 0x" << std::hex << index_curr << std::dec << endl;
            cout << "           Size of compressed section: " << (index - index_curr) / 1024 << "kB" << endl;
            cout << "           Size of decompressed section: " << decomp_size / 1024 << "kB" << endl;
        }
        else {
            buff = setReverse(chunk) >> 24;
            out_file.put(buff);
            index += 0x01;
        }
    }

    in_file.close();
    out_file.close();

    cout << num_gprs << " sections have been successfully decompressed in this file" << endl;
}


int main(int argc, char *argv[]) {
    string prgm = argv[0];
    prgm.erase(remove(prgm.begin(), prgm.end(), '\"'), prgm.end());
    prgm = prgm.substr(prgm.find_last_of("\\/") + 1);
    prgm = prgm.substr(0, prgm.find_last_of('.'));


    if (argc < 2) {
        cout << "Usage: " << prgm << " <infile(s)>\n"
             << endl;
    }
    else {
        for (int fileIndex = 1; fileIndex < argc; ++fileIndex) {
            string inFile = argv[fileIndex];
            inFile.erase(remove(inFile.begin(), inFile.end(), '\"'), inFile.end());

            searchGPRS(inFile);
            cout << endl;
        }
    }

    return 0;
}
