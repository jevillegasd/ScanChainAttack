#pragma once

#include<stdlib.h>
#include<stdio.h>
#include<sstream>  //Buffer
#include<ostream>  //Flush
#include<conio.h>
#include<string.h>
#include<windows.h>

constexpr int DEFAULT_BAUDRATE = 9600;
constexpr int DEFAULT_STOPBIT = ONESTOPBIT;
constexpr int DEFAULT_PARITY = PARITY_NONE;
constexpr int DEFAULT_BYTESIZE = DATABITS_8;
constexpr int DEFAULT_FDTRCTRL = 0;
constexpr int DEFAULT_FRTSCTRL = 0;


// Fucntion definitions
void systemError(char* name);
HANDLE setComm(char port[]);
bool test_comm(HANDLE m_hCommPor);
bool setup_comm(HANDLE m_hCommPor);
bool printf(HANDLE m_hCommPort, uint8_t send[], int number_of_bytes);

std::string readf(HANDLE m_hCommPort);