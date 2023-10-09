#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <cstdint>
#include <sys/stat.h>

#pragma pack(push,1)
struct chunk_head
{
    uint32_t Name, Size;
    std::string name_str();
};

struct GEN8_head
{
    chunk_head head;
    char DebugDisabled, BytecodeVersion;
    uint16_t Unknown1;
    uint32_t sFilename, sConfig, LastObj, LastTile, GameID,
        Unknown2[4], sName, Major, Minor, Release, Build,
        DefWindowWidth, DefWindowHeight, InfoFlags;
    char LicenseMD5[16];
    uint32_t LicenseCRC32;
    uint64_t Timestamp;
    uint32_t sDisplayName, ActiveTargets, Unknown3[4], SteamAppId, NumberCount;
    // uint32_t Numbers[NumberCount];
};

struct OPTN_head
{
    chunk_head head;
    uint32_t Unknown1[2], InfoFlags, Unknown2[12];
    uint32_t NumConstants;
};

struct OPTN_listitem
{
    uint32_t Name, Value;
};
#pragma pack(pop)

// Convert chunk Name field into printable string
std::string chunk_head::name_str()
{
    std::string s;

    s.resize(4);
    *((uint32_t*)&s[0]) = Name;
    
    return s;
}

size_t filesize(const char* filename)
{
    struct stat statbuf;
    return (stat(filename, &statbuf) == -1) ? 0 : statbuf.st_size;
}

// Extract string from data file by position
std::string data_string(std::ifstream& file_stream, uint32_t pos)
{
    // Save current seek position
    auto saved_pos = file_stream.tellg();
    file_stream.seekg(pos);
    
    // Read null-terminated string at offset (UTF-8)
    std::string s;
    std::getline(file_stream, s, '\0');

    // Restore original seek position and return read string
    file_stream.seekg(saved_pos);
    return s;
}

size_t chrtol(char c)
{
    return (((size_t)c) & 0xff);
}

int error(const char* msg)
{
    std::cerr << msg << '\n';
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return error("Input data file required as argument!");

    // Open data file
    size_t data_size = filesize(argv[1]);
    
    if (data_size < sizeof(chunk_head) + sizeof(GEN8_head))
        return error("Data file too small!");

    std::ifstream data;
    data.open(argv[1], std::ios::binary);

    if (!data.is_open())
        return error("Could not open data file!");

    // Intro
    std::cout << "Parsing data file (all values in hex)\nFile size:\t" << std::hex << data_size << '\n';
    size_t pos = 0;

    // Read FORM chunk
    chunk_head form;
    data.read((char*)&form, sizeof(form));
    pos += sizeof(form);

    std::cout << "[0]\t== FORM ==\nName:\t" << form.name_str() << "\nSize:\t" << form.Size << "\n\n";

    // Read GEN8 chunk
    GEN8_head gen;
    data.read((char*)&gen, sizeof(gen));
    pos += sizeof(gen);

    std::cout << "[8]\t== GEN8 ==\nName:\t" << gen.head.name_str() << "\nSize:\t" << gen.head.Size << '\n';
    std::cout << "DebugDisabled:\t" << chrtol(gen.DebugDisabled) << "\nBytecodeVersion:\t" << chrtol(gen.BytecodeVersion) << '\n';
    std::cout << "Unknown1:\t" << gen.Unknown1 << '\n';
    std::cout << "sFilename:\t[" << gen.sFilename << "] " << data_string(data, gen.sFilename) << '\n';
    std::cout << "sConfig:\t[" << gen.sConfig << "] " << data_string(data, gen.sConfig) << '\n';
    std::cout << "LastObj:\t" << gen.LastObj << "\nLastTile:\t" << gen.LastTile << "\nGameID:\t" << gen.GameID << '\n';
    std::cout << "Unknown2:\t" << gen.Unknown2[0] << ' ' << gen.Unknown2[1] << '\n';
    std::cout << "sName:\t[" << gen.sName << "] " << data_string(data, gen.sName) << '\n';
    std::cout << "Major:\t" << gen.Major << "\nMinor:\t" << gen.Minor << "\nRelease:\t" << gen.Release << "\nBuild:\t" << gen.Build << '\n';
    std::cout << "DefWindowWidth:\t" << gen.DefWindowWidth << "\nDefWindowHeight:\t" << gen.DefWindowHeight << '\n';
    std::cout << "InfoFlags:\t" << gen.InfoFlags << " (Studio version " << ((gen.InfoFlags & 0x0E00) >> 9) << ")\n";

    std::cout << "LicenseMD5: ";
    for (size_t i = 0; i < 16; i++)
        std::cout << chrtol(gen.LicenseMD5[i]) << ' ';
    std::cout << '\n';

    std::cout << "LicenseCRC32:\t" << gen.LicenseCRC32 << "\nTimeStamp:\t" << gen.Timestamp << '\n';
    std::cout << "sDisplayName:\t[" << gen.sDisplayName << "] " << data_string(data, gen.sDisplayName) << '\n';
    std::cout << "ActiveTargets:\t" << gen.ActiveTargets << '\n';
    std::cout << "Unknown3:\t" << gen.Unknown3[0] << ' ' << gen.Unknown3[1] << ' ' << gen.Unknown3[2] << ' ' << gen.Unknown3[3] << '\n';
    std::cout << "SteamAppId:\t" << gen.SteamAppId << '\n';
    std::cout << "NumberCount:\t" << gen.NumberCount << '\n';

    std::cout << "Numbers:\t";

    for (size_t i = 0; i < gen.NumberCount; i++)
    {
        uint32_t number;
        data.read((char*)&number, sizeof(number));
        pos += sizeof(number);

        std::cout << number << ' ';
    }

    std::cout << "\n\n";

    if (data_size < pos + sizeof(chunk_head))
        return error("EOF");

    OPTN_head optn;
    data.read((char*)&optn, sizeof(optn));
    
    std::cout << '[' << pos << "]\t == OPTN == \nName:\t" << optn.head.name_str() << "\nSize:\t" << optn.head.Size << '\n';
    pos += sizeof(optn);

    std::cout << "Unknown1:\t" << optn.Unknown1[0] << ' ' << optn.Unknown1[1] << '\n';
    std::cout << "InfoFlags:\t" << optn.InfoFlags << '\n';

    std::cout << "Unknown2:\t";
    for (size_t i = 0; i < 12; i++)
        std::cout << optn.Unknown2[i] << ' ';

    std::cout << "\nConstantMap\n\tSize:\t" << optn.NumConstants << '\n';
    std::cout << "\tElements:\n";

    for (size_t i = 0; i < optn.NumConstants; i++)
    {
        OPTN_listitem item;
        data.read((char*)&item, sizeof(item));
        pos += sizeof(item);

        std::cout << "\t\tName:\t" << item.Name << "\t" << data_string(data, item.Name) << '\n';
        std::cout << "\t\tValue:\t" << item.Value << "\t" << data_string(data, item.Value) << "\n\n";
    }

    return 0;
}
