// Simple Serial Communication Library
// JVillegas 2020

#include"simpleSerial.h"
#include <fstream>

//Global variables
DCB dcbSerialParams = { 0 };  // Initializing DCB structure
COMMTIMEOUTS timeouts = { 0 };  //Initializing timeouts structure

HANDLE setComm(char port[]) {
    HANDLE CommPort = CreateFileA(
        port,
        GENERIC_READ | GENERIC_WRITE,  // access ( read and write)
        0,                           // (share) 0:cannot share the COM port
        NULL,                        // security  (None)
        OPEN_EXISTING,               // creation : open_existing
        0,                           // 
        NULL);                       // no templates file for COM port...
    return CommPort;
}

bool setup_comm(HANDLE m_hCommPort) {
    bool state;
    if (GetCommState(m_hCommPort, &dcbSerialParams)) {
        dcbSerialParams.BaudRate = CBR_115200;      //BaudRate  = 115200
        dcbSerialParams.ByteSize = 8;               //ByteSize  = 8
        dcbSerialParams.StopBits = ONESTOPBIT;      //StopBits  = 1
        dcbSerialParams.Parity = NOPARITY;          //Parity    = None
        dcbSerialParams.fBinary = TRUE;
        dcbSerialParams.fParity = TRUE;
        state = SetCommState(m_hCommPort, &dcbSerialParams);
    }
    else
        state = false;

    if (state && GetCommTimeouts(m_hCommPort, &timeouts)) {
        timeouts.ReadIntervalTimeout = 1;
        timeouts.ReadTotalTimeoutConstant = 1;
        timeouts.ReadTotalTimeoutMultiplier = 1;
        timeouts.WriteTotalTimeoutConstant = 1;
        timeouts.WriteTotalTimeoutMultiplier = 1;
        state = SetCommTimeouts(m_hCommPort, &timeouts);
    }
    else
        state = false;

    return state;
}

bool test_comm(HANDLE m_hCommPort) {
    if (m_hCommPort == INVALID_HANDLE_VALUE) {
        systemError((char*)"opening the port ");
        return false;
    }
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    if (!GetCommState(m_hCommPort, &dcbSerialParams)) {
        systemError((char*)"reading the COM state ");
        CloseHandle(m_hCommPort);
        return false;
    }
    return true;
}

bool printf(HANDLE m_hCommPort, uint8_t send[], int number_of_bytes) {
    DWORD BytesWritten = 0, eventMask = 0, bufferSize = 0;
    std::stringbuf buffer;
    bool status = false;

    //Sends a string to the UART
    status = SetCommMask(m_hCommPort, EV_TXEMPTY); // The last character in the output buffer was sent.
    status &= WriteFile(m_hCommPort,        // Handle to the Serialport
        send,               // Data to be written to the port
        number_of_bytes,    // No of bytes to write into the port
        &BytesWritten,      // No of bytes written to the port
        NULL);

    if (status)
        status = WaitCommEvent(m_hCommPort, &eventMask, NULL);
    
    return status;
}

std::string readf(HANDLE m_hCommPort) {
    DWORD BytesWritten = 0, eventMask = 0, totalBufferSize = 0, inBufferSize = 0;
    std::stringbuf buffer;
    bool status = false;

    if(SetCommMask(m_hCommPort, EV_RXCHAR))
        status = WaitCommEvent(m_hCommPort, &eventMask, NULL); // Timeoput not working well it's staying in this wait.


    if (status) {
        char pointBuffer;
        do {
            if (ReadFile(m_hCommPort, &pointBuffer, 1, &inBufferSize, NULL) != 0) {
                if (inBufferSize > 0) {
                    totalBufferSize += inBufferSize;
                    buffer.sputn(&pointBuffer, inBufferSize);
                }
                else
                    break;
            }
        } while (inBufferSize > 0);
    }

    std::string ret = buffer.str();
    return ret;
}