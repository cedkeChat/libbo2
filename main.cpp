#include "fastfile.hpp"

#include <Windows.h>

static char szFileName[MAX_PATH] = "";
static OPENFILENAMEA file_data;

const char* request_open_file() {
    ZeroMemory(&file_data, sizeof(file_data));
    file_data.lStructSize = sizeof(file_data);
    file_data.lpstrFilter = "All Files (*.*)\0*.*\0";
    file_data.lpstrFile = szFileName;
    file_data.nMaxFile = MAX_PATH;
    file_data.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    file_data.lpstrDefExt = "txt";
    GetOpenFileNameA(&file_data);
    return file_data.lpstrFile;
}
// clang-format off
//
// g++ main.cpp -g -std=c++20 -o main.exe -ltomcrypt -lcomdlg32 -lz
//
// clang-format on

int main(int argc, char** argv) {
    printf("Hello world!\n");

    std::string fpath(request_open_file());
    FastFile ff(fpath, FastFile::WiiU, FastFile::WiiU, FastFile::Big, FastFile::Big);
    ff.ValidateHeader();
    ff.Decrypt();

    std::printf("Done!\n");

    return 0;
}