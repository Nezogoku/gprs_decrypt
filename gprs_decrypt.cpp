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


//Rewrite of bnnm's LZGPRS thing
void DecryptGPRS(uint32_t &index, uint32_t dst_size) {
    int shift, addr;
    char buff, cur;
    auto cmpBits = [&]() -> bool { return (cur >> shift--) & 0x01; };
    
    //cout << "Decompressing" << endl;
    char *dst = new char[dst_size] {};
    //cout << "Created temporary array with size " << dst_size << endl;
    uint32_t dst_curr = 0;
    //cout << "Set dst_curr to 0" << endl;
    uint32_t dst_next = dst_curr;
    //cout << "Set dst_next to " << dst_next << endl;
    uint32_t src_curr = index + 0x08;
    //cout << "Set src_curr to " << src_curr << endl;
    uint32_t src_next = src_curr + 0x01;
    //cout << "Set src_next to " << src_next << endl;

    
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

            if (cmpBits()) break;

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

        if (!cmpBits()) {
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
            nib_temp = cmpBits();

            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits();

            if (shift < 0) {
               in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits();

            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits();

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

            if (!cmpBits()) break;

            if (shift < 0) {
                in_file.seekg(src_curr++);
                in_file.get(cur);
                shift = 7;
            }

            //cout << "Count loop alter count" << endl;
            count = count * 2 + ((cmpBits()) ? 1 : 0);
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
    } while (in_file.get(buff) && dst_curr < dst_size);
    //cout << "Stop decompressing" << endl;

    out_file.write((const char*)(dst), dst_size);
    //cout << "Copied decompressed to outfile" << endl;

    index = src_next;
}

void SkipGARC(uint32_t &index) {
    in_file.seekg(index);
    auto *in_dat = in_file.rdbuf();
    uint32_t tmp = 0x08;
    
    //Get SUB-HEADER chunk location
    in_file.seekg(index + tmp);
    in_file.read((char*)(&tmp), sizeof(uint32_t));
    
    //Get FILE chunk location
    in_file.seekg(index + (tmp + 0x04));
    in_file.read((char*)(&tmp), sizeof(uint32_t));

    //Get NAME chunk location
    in_file.seekg(index + (tmp + 0x04));
    in_file.read((char*)(&tmp), sizeof(uint32_t));

    //Get DATA chunk location
    in_file.seekg(index + (tmp + 0x04));
    in_file.read((char*)(&tmp), sizeof(uint32_t));

    //Get TERM location
    in_file.seekg(index + (tmp + 0x04));
    in_file.read((char*)(&tmp), sizeof(uint32_t));

    char *dst = new char[tmp + 0x04] {};
    in_dat->sgetn(dst, tmp + 0x04);
    out_file.write((const char*)(dst), tmp + 0x04);

    index += (tmp + 0x04);
}

void searchGPRS(string filename) {
    const uint32_t GPRS = 0x47505253, GARC = 0x47415243;
    uint32_t index = 0x00, chunk = 0x00;
    int num_gprs = 0;
    char buff;
    auto getBE32 = [&]() -> uint32_t {
        chunk = 0x00;
        for (int c = 0; c < 4; ++c) {
            in_file.get(buff);
            chunk = (chunk << 8) | (buff & 0xFF);
        }
        return chunk;
    };


    in_file.open(filename.c_str(), ios::in | ios::binary);
    if (!in_file.is_open()) {
        cerr << "Unable to read \"" << filename << "\"" << endl;
        return;
    }
    else cout << filename.substr(filename.find_last_of("\\/") + 1)
              << " opened for decompressing" << endl;

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
        chunk = getBE32();

        if (chunk == GARC) SkipGARC(index);
        else if (chunk == GPRS) {
            num_gprs += 1;

            //Grabs size of decompressed section from GPRS header thing
            chunk = getBE32();

            //cout << "Current index is " << index << endl;
            uint32_t index_curr = index;
            DecryptGPRS(index, chunk);
            
            cout << "Decompressed the section at offset 0x" << std::hex << index_curr << std::dec << endl;
            cout << "           Size of compressed section: " << (index - index_curr) / 1024 << "kB" << endl;
            cout << "           Size of decompressed section: " << chunk / 1024 << "kB" << endl;
        }
        else {
            for (int c = 0; c < 4; ++c, ++index) {
                buff = (chunk >> (8 * (3 - c))) & 0xFF;
                out_file.put(buff);
            }
        }
        
        //Ensures index is multiple of 4
        index += (!index) ? 0x04 : (0x04 - (index % 0x04)) % 0x04;
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
