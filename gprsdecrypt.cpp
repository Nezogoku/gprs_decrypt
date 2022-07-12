#include <iostream>
#include <algorithm>
#include <fstream>
#include <vector>
#include <cstdio>
#include <string>
#include <direct.h>
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

using namespace std;

#define GPRS 0x47505253
#define GARC 0x47415243


int DecryptGPRS(ifstream &section, int index, ofstream &out_file) {
    uint32_t GPRS_start = 0x00;
    uint32_t GARC_start = 0xA210D0;

    uint32_t v0 = 0x80;         //0x1CFD8;
    uint32_t v1 = 0x00;         //0x00;
    uint32_t a0 = GARC_start;   //GARC_start;
    uint32_t a1 = 0x09;         //0x08;
    uint32_t a2 = 0x0A;         //0x00;
    uint32_t a3 = 0x08;         //0x08;
    uint32_t t0 = 0x01;         //0x00;
    uint32_t t1 = 0x00;         //0x00;
    uint32_t t2 = -0x0100;      //0x00;
    uint32_t t3 = 0x00;         //0x00;
    uint32_t t4 = 0x00;         //0x00;
    uint32_t at = 0x00;         //0x00;

    bool running = true,
         jump = false;

    int jump_count = 0;

    uint32_t curr_addr = 0x00,
             jump_addr = 0x00,
             end_addr = 0x00;


    vector<uint32_t> MAGIC_file = {0x350,0x348,0x340,0x338,0x330,0x328,0x320,0x318,0x86C,0x864,0x85C,0x854,0x84C,0x844,0x83C,0x834};
    vector<char> temp_file;

    while (running) {
        uint32_t t_addr;
        char buff;

        switch(curr_addr) {
            case 0x00:
                section.seekg(index + 0x08);
                section.get(buff);
                a3 = buff;

                if (0x08 > end_addr) end_addr = 0x08;
                curr_addr = 0x18;
                break;

            case 0x18:
                if (v0 != 0x00) {
                    jump = true;
                    jump_addr = 0x34;
                }

                curr_addr += 0x04;
                break;

            case 0x1C:
                t1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x20:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    a3 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                a1 = a2;
                v0 = int32_t(0x80);
                a2 = a1 + int32_t(0x01);
                t1 = a3 & v0;

                curr_addr += 0x14;
                break;

            case 0x34:
                if (t1 == 0x00) {
                    jump = true;
                    jump_addr = 0x48;
                }

                curr_addr += 0x04;
                break;

            case 0x38:
                t3 = v0 >> 0x01;
                v0 = t3;

                curr_addr += 0x08;
                break;

            case 0x40:
                jump = true;
                jump_addr = 0x50;
                curr_addr += 0x04;
                break;

            case 0x44:
                t1 = t0;
                curr_addr += 0x04;
                break;

            case 0x48:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x4C:
                t1 = int32_t(0x00);
                curr_addr += 0x04;
                break;

            case 0x50:
                if (t1 != 0x00) {
                    jump = true;
                    jump_addr = 0x70;
                }

                curr_addr += 0x04;
                break;

            case 0x54:
                curr_addr += 0x04;
                break;

            case 0x58:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    t1 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    t1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x5C:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x60:
                if (a0 >= GARC_start) {
                    buff = t1;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x64:
                a0 += int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x68:
                jump = true;
                jump_addr = 0x0364;
                curr_addr += 0x04;
                break;

            case 0x6C:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x70:
                if (t3 != 0x00) {
                    jump = true;
                    jump_addr = 0x8C;
                }

                curr_addr += 0x04;
                break;

            case 0x74:
                t1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x78:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    a3 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x7C:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x80:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x84:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x88:
                t1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x8C:
                if (t1 == 0x00) {
                    jump = true;
                    jump_addr = 0xA0;
                }

                curr_addr += 0x04;
                break;

            case 0x90:
                v0 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x94:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x98:
                jump = true;
                jump_addr = 0xA8;
                curr_addr += 0x04;
                break;

            case 0x9C:
                t1 = t0;
                curr_addr += 0x04;
                break;

            case 0xA0:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0xA4:
                t1 = int32_t(0x00);
                curr_addr += 0x04;
                break;

            case 0xA8:
                if (t1 != t0) {
                    jump = true;
                    jump_addr = 0x01A4;
                }

                curr_addr += 0x04;
                break;

            case 0xAC:
                curr_addr += 0x04;
                break;

            case 0xB0:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    t1 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    t1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0xB4:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0xB8:
                t1 = t1 | t2;
                curr_addr += 0x04;
                break;

            case 0xBC:
                if (v0 != 0x00) {
                    jump = true;
                    jump_addr = 0xD4;
                }

                curr_addr += 0x04;
                break;

            case 0xC0:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0xC4:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0xC8:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0xCC:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0xD0:
                v1 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0xD4:
                t3 = a3 & v1;
                curr_addr += 0x04;
                break;

            case 0xD8:
                if (t3 == 0x00) {
                    jump = true;
                    jump_addr = 0xEC;
                }

                curr_addr += 0x04;
                break;

            case 0xDC:
                v1 = v1 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0xE0:
                t3 = v1;
                curr_addr += 0x04;
                break;

            case 0xE4:
                jump = true;
                jump_addr = 0xF4;
                curr_addr += 0x04;
                break;

            case 0xE8:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0xEC:
                t3 = v1;
                curr_addr += 0x04;
                break;

            case 0xF0:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0xF4:
                if (v1 != 0x00) {
                    jump = true;
                    jump_addr = 0x010C;
                }

                curr_addr += 0x04;
                break;

            case 0xF8:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0xFC:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x100:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x104:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x108:
                t3 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x10C:
                v0 = a3 & t3;
                curr_addr += 0x04;
                break;

            case 0x110:
                if (v0 == 0x00) {
                    jump = true;
                    jump_addr = 0x0124;
                }

                curr_addr += 0x04;
                break;

            case 0x114:
                t3 = t3 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x118:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x11C:
                jump = true;
                jump_addr = 0x012C;
                curr_addr += 0x04;
                break;

            case 0x120:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x124:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x128:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0x12C:
                if (t3 != 0x00) {
                    jump = true;
                    jump_addr = 0x0144;
                }

                curr_addr += 0x04;
                break;

            case 0x130:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0x134:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x138:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x13C:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x140:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x144:
                v1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x148:
                if (v1 == 0x00) {
                    jump = true;
                    jump_addr = 0x015C;
                }

                curr_addr += 0x04;
                break;

            case 0x14C:
                t3 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x150:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x154:
                jump = true;
                jump_addr = 0x0164;
                curr_addr += 0x04;
                break;

            case 0x158:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x15C:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x160:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0x164:
                if (t3 != 0x00) {
                    jump = true;
                    jump_addr = 0x017C;
                }

                curr_addr += 0x04;
                break;

            case 0x168:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0x16C:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x170:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x174:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x178:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x17C:
                t3 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x180:
                if (t3 == 0x00) {
                    jump = true;
                    jump_addr = 0x0194;
                }

                curr_addr += 0x04;
                break;

            case 0x184:
                v0 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x188:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x18C:
                jump = true;
                jump_addr = 0x019C;
                curr_addr += 0x04;
                break;

            case 0x190:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x194:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x198:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0x19C:
                jump = true;
                jump_addr = 0x01C0;
                curr_addr += 0x04;
                break;

            case 0x1A0:
                t1 = t1 + int32_t(-0xFF);
                curr_addr += 0x04;
                break;

            case 0x1A4:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    t1 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    t1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x1A8:
                if (t1 == 0x00) {
                    jump = true;
                    jump_addr = 0x01B8;
                }

                curr_addr += 0x04;
                break;

            case 0x1AC:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x1B0:
                jump = true;
                jump_addr = 0x01C0;
                curr_addr += 0x04;
                break;

            case 0x1B4:
                t1 = t1 | t2;
                curr_addr += 0x04;
                break;

            case 0x1B8:
                jump = true;
                jump_addr = 0x036C;
                curr_addr += 0x04;
                break;

            case 0x1BC:
                curr_addr += 0x04;
                break;

            case 0x1C0:
                t3 = t0;
                curr_addr += 0x04;
                break;

            case 0x1C4:
                if (v0 != 0x00) {
                    jump = true;
                    jump_addr = 0x01E0;
                }

                curr_addr += 0x04;
                break;

            case 0x1C8:
                v0 = a3 & v1;
                curr_addr += 0x04;
                break;

            case 0x1CC:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x1D0:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x1D4:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x1D8:
                v1 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x1DC:
                v0 = a3 & v1;
                curr_addr += 0x04;
                break;

            case 0x1E0:
                if (v0 == 0x00) {
                    jump = true;
                    jump_addr = 0x01F4;
                }

                curr_addr += 0x04;
                break;

            case 0x1E4:
                v1 = v1 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x1E8:
                v0 = v1;
                curr_addr += 0x04;
                break;

            case 0x1EC:
                jump = true;
                jump_addr = 0x01FC;
                curr_addr += 0x04;
                break;

            case 0x1F0:
                t4 = t0;
                curr_addr += 0x04;
                break;

            case 0x1F4:
                v0 = v1;
                curr_addr += 0x04;
                break;

            case 0x1F8:
                t4 = int32_t(0x00);
                curr_addr += 0x04;
                break;

            case 0x1FC:
                if (t4 != t0) {
                    jump = true;
                    jump_addr = 0x0244;
                }

                curr_addr += 0x04;
                break;

            case 0x200:
                curr_addr += 0x04;
                break;

            case 0x204:
                if (v1 != 0x00) {
                    jump = true;
                    jump_addr = 0x021C;
                }

                curr_addr += 0x04;
                break;

            case 0x208:
                t3 = t3 << 0x01;
                curr_addr += 0x04;
                break;

            case 0x20C:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x210:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x214:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x218:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x21C:
                v1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x220:
                if (v1 == 0x00) {
                    jump = true;
                    jump_addr = 0x0234;
                }

                curr_addr += 0x04;
                break;

            case 0x224:
                v0 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x228:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x22C:
                jump = true;
                jump_addr = 0x023C;
                curr_addr += 0x04;
                break;

            case 0x230:
                t3 = t3 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x234:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x238:
                t3 = t3;
                curr_addr += 0x04;
                break;

            case 0x23C:
                jump = true;
                jump_addr = 0x01C4;
                curr_addr += 0x04;
                break;

            case 0x240:
                curr_addr += 0x04;
                break;

            case 0x244:
                if (t3 < 0x7) a2 = 1;
                else a2 = 0;

                curr_addr += 0x04;
                break;

            case 0x248:
                if (a2 == 0x00) {
                    jump = true;
                    jump_addr = 0x0278;
                    curr_addr += 0x04;
                }
                else curr_addr += 0x08;
                break;

            case 0x24C:
                t3 = t3 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x250:
                if (t3 < 0) {
                    jump = true;
                    jump_addr = 0x364;
                }

                curr_addr += 0x04;
                break;

            case 0x254:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x258:
                v1 = a0 + t1;
                curr_addr += 0x04;
                break;

            case 0x25C:
                if ((v1 >= GPRS_start) && (v1 < GARC_start)) {
                    section.seekg(index + v1);
                    section.get(buff);
                    v1 = buff;

                    if (v1 > end_addr) end_addr = v1;
                }
                if (v1 >= GARC_start) {
                    t_addr = v1 - GARC_start;

                    v1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x260:
                t3 = t3 + int32_t(-0x01);
                curr_addr += 0x04;
                break;

            case 0x264:
                if (a0 >= GARC_start) {
                    buff = v1;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x268:
                if ((int32_t)t3 >= 0) {
                    jump = true;
                    jump_addr = 0x0258;
                }

                curr_addr += 0x04;
                break;

            case 0x26C:
                a0 = a0 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x270:
                jump = true;
                jump_addr = 0x0364;
                curr_addr += 0x04;
                break;

            case 0x274:
                curr_addr += 0x04;
                break;

            case 0x278:
                a2 = t3 >> 0x3;
                curr_addr += 0x04;
                break;

            case 0x27C:
                t3 = t3 & 0x7;
                curr_addr += 0x04;
                break;

            case 0x280:
                v1 = t3 + int32_t(-0x08);
                curr_addr += 0x04;
                break;

            case 0x284:
                a0 = a0 + v1;
                curr_addr += 0x04;
                break;

            case 0x288:
                if (t3 < 0x08) v1 = 1;
                else v1 = 0;

                curr_addr += 0x04;
                break;

            case 0x28C:
                if (v1 == 0x00) {
                    jump = true;
                    jump_addr = 0x02AC;
                }

                curr_addr += 0x04;
                break;

            case 0x290:
                t1 = a0 + t1;
                curr_addr += 0x04;
                break;

            case 0x294:
                t3 = t3 << 0x02;
                curr_addr += 0x04;
                break;

            case 0x298:
                at = 0x00;
                curr_addr += 0x04;
                break;

            case 0x29C:
                at = at + t3;
                curr_addr += 0x04;
                break;

            case 0x2A0:
                at = MAGIC_file[at / 4];
                curr_addr += 0x04;
                break;

            case 0x2A4:
                jump = true;
                jump_addr = at;
                curr_addr += 0x04;
                break;

            case 0x2A8:
                curr_addr += 0x04;
                break;

            case 0x2AC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    section.seekg(index + t1);
                    section.get(buff);
                    t3 = buff;

                    if (t1 > end_addr) end_addr = t1;
                }

                if (t1 >= GARC_start) {
                    t_addr = t1 - GARC_start;
                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2B0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2B4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x01 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x01 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2B8:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2BC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x02 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x02 + t1 - GARC_start;
                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2C0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2C4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x3 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x3 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2C8:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2CC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x04 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x04 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2D0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2D4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x05 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x05 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2D8:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2DC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x6 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x6 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2E0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2E4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x7 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    v1 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x7 + t1 - GARC_start;

                    v1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2E8:
                t3 = a2;
                curr_addr += 0x04;
                break;

            case 0x2EC:
                a2 = a0 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x2F0:
                if (a0 >= GARC_start) {
                    buff = v1;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2F4:
                t1 = t1 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x2F8:
                a0 = t3 + int32_t(-0x01);
                curr_addr += 0x04;
                break;

            case 0x2FC:
                t3 = a0;
                curr_addr += 0x04;
                break;

            case 0x300:
                a0 = a2;
                curr_addr += 0x04;
                break;

            case 0x304:
                a2 = t3;
                curr_addr += 0x04;
                break;

            case 0x308:
                if ((int32_t)a2 >= 0) {
                    jump = true;
                    jump_addr = 0x02AC;
                }

                curr_addr += 0x04;
                break;

            case 0x30C:
                curr_addr += 0x04;
                break;

            case 0x310:
                jump = true;
                jump_addr = 0x0364;
                curr_addr += 0x04;
                break;

            case 0x314:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x318:
                jump = true;
                jump_addr = 0x02B8;
                curr_addr += 0x04;
                break;

            case 0x31C:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x01 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x01 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x320:
                jump = true;
                jump_addr = 0x02C0;
                curr_addr += 0x04;
                break;

            case 0x324:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x02 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x02 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x328:
                jump = true;
                jump_addr = 0x02C8;
                curr_addr += 0x04;
                break;

            case 0x32C:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x3 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x3 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x330:
                jump = true;
                jump_addr = 0x02D0;
                curr_addr += 0x04;
                break;

            case 0x334:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x04 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x04 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x338:
                jump = true;
                jump_addr = 0x02D8;
                curr_addr += 0x04;
                break;

            case 0x33C:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x05 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x05 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x340:
                jump = true;
                jump_addr = 0x02E0;
                curr_addr += 0x04;
                break;

            case 0x344:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x6 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x6 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x348:
                jump = true;
                jump_addr = 0x02E4;
                curr_addr += 0x04;
                break;

            case 0x34C:
                curr_addr += 0x04;
                break;

            case 0x350:
                t3 = a2;
                curr_addr += 0x04;
                break;

            case 0x354:
                a2 = a0 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x358:
                t1 = t1 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x35C:
                jump = true;
                jump_addr = 0x02FC;
                curr_addr += 0x04;
                break;

            case 0x360:
                a0 = t3 + int32_t(-0x01);
                curr_addr += 0x04;
                break;

            case 0x364:
                jump = true;
                jump_addr = 0x18;
                curr_addr += 0x04;
                break;

            case 0x368:
                curr_addr += 0x04;
                break;

            case 0x36C:
                running = false;
                break;
        }

        if(jump_count >= 1) {
            jump_count = 0;
            curr_addr = jump_addr;
        }

        if(jump) {
            jump = false;
            jump_count = 1;
        }
    }

    //cout << "Program took " << ins << " instructions to decompress this file" << endl;
    //cout << "Compressed section ends at 0x" << hex << end_addr << dec << endl;

    out_file.write((const char*)(temp_file.data()), temp_file.size());

    vector<char> ().swap(temp_file);

    return end_addr + 0x01;
}


int SkipGARC(ifstream &section, int index, ofstream &out_file) {
    uint32_t cfileAddr;                                                         // 32 bit le, FILE chunk location
    uint32_t cnameAddr;                                                         // 32 bit le, NAME chunk location
    uint32_t cdataAddr;                                                         // 32 bit le, DATA chunk location
    uint32_t termAddr;                                                          // 32 bit le, TERM location

    uint32_t tempAddr = 0x14;

    section.seekg(index + tempAddr);
    section.read((char*)(&cfileAddr), sizeof(uint32_t));

    tempAddr = cfileAddr + 0x04;
    section.seekg(index + tempAddr);
    section.read((char*)(&cnameAddr), sizeof(uint32_t));

    tempAddr = cnameAddr + 0x04;
    section.seekg(index + tempAddr);
    section.read((char*)(&cdataAddr), sizeof(uint32_t));

    tempAddr = cdataAddr + 0x04;
    section.seekg(index + tempAddr);
    section.read((char*)(&termAddr), sizeof(uint32_t));

    section.seekg(index);
    vector<char> garc_section;
    for (int i = 0; i < (termAddr + 0x04); ++i) {
        char buff;
        section.get(buff);
        garc_section.push_back(buff);
    }

    out_file.write((const char*)(garc_section.data()), garc_section.size());

    vector<char> ().swap(garc_section);

    return termAddr + 0x04;
}

void searchGPRS(string filename) {
    string extr_filename = filename.substr(filename.find_last_of("\\/") + 1);
    string workdir = filename.substr(0, filename.find_last_of("\\/") + 1);

    _chdir(workdir.c_str());

    ifstream in_file(filename.c_str(), ios::binary);
    if (!in_file.is_open()) {
        cerr << "Unable to open \"" << filename << "\"" << endl;
        return;
    }

    cout << "Reading file . . ." << endl;

    char buff;

    int num_gprs = 0,
        total_gprs = 0;

    uint32_t index = 0x00,
             decomp_size = 0x00,
             sizeofsect = 0x00,
             chunk;

    cout << extr_filename << " opened for decompressing" << endl;


    string new_folder = extr_filename.substr(0, extr_filename.find_last_of('.'));
    for_each(new_folder.begin(), new_folder.end(), [](char &ch) {ch = tolower(ch);});

    workdir += new_folder;
    _mkdir(workdir.c_str());
    _chdir(workdir.c_str());


    ofstream extr_out;
    extr_out.open(extr_filename.c_str(), ios::binary);

    while (in_file.get(buff)) {
        in_file.seekg(index);
        in_file.read((char*)(&chunk), sizeof(uint32_t));

        if (htonl(chunk) == GPRS) {
            num_gprs += 1;

            //Grabs size of decompressed section from GPRS header thing
            in_file.seekg(index + 0x04);
            in_file.read((char*)(&decomp_size), sizeof(uint32_t));
            decomp_size = htonl(decomp_size);

            //cout << "Current index is " << index << endl;
            sizeofsect = DecryptGPRS(in_file, index, extr_out);
            cout << "Decompressed the section at offset 0x" << hex << index << dec << endl;
            cout << "           Size of compressed section: " << sizeofsect / 1024 << "kB" << endl;
            cout << "           Size of decompressed section: " << decomp_size / 1024 << "kB" << endl;

            index += sizeofsect;
        }
        else if (htonl(chunk) == GARC) {
            sizeofsect = SkipGARC(in_file, index, extr_out);
            index += sizeofsect;
        }
        else {
            chunk = htonl(chunk);
            buff = chunk >> 24;
            extr_out.put(buff);
            index += 0x01;
        }
    }


    extr_out.close();

    cout << num_gprs << " sections have been successfully decompressed in_file this file" << endl;
}

int main(int argc, char *argv[]) {
    string prgm = argv[0];
    prgm.erase(remove(prgm.begin(), prgm.end(), '\"'), prgm.end());
    prgm = prgm.substr(prgm.find_last_of("\\/") + 1, prgm.find_last_of('.'));


    if (argc < 2) {
        cout << "Usage: " << prgm << " <infile(s)>\n"
             << endl;
        return 0;
    }

    for (int fileIndex = 1; fileIndex < argc; ++fileIndex) {
        string inFile = argv[fileIndex];
        inFile.erase(remove(inFile.begin(), inFile.end(), '\"'), inFile.end());

        searchGPRS(inFile);
    }

    return 0;
}
