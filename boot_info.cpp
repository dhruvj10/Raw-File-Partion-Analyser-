//Dhruv Jain  
//CSE 469
//HW1, ASU ID - 1219324847



#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sstream>
#include <map>

bool CheckGPT(const std::vector<char>& data);


//Helper func to parse the string from the csv of PArtitiontype
 std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}
//Function to get the partitionTypes from the csv 
std::map<int, std::string> readPartitionTypes(const std::string& filename) {
    std::map<int, std::string> partitionTypes;

    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) 
    {
        std::istringstream iss(line);
        std::string hexValue, typeName;

        if (std::getline(iss, hexValue, ',') && std::getline(iss, typeName)) 
        {
            hexValue = trim(hexValue);
        typeName = trim(typeName);
            try 
            {
         int intValue = std::stoi(hexValue, nullptr, 16);
                partitionTypes[intValue] = typeName;
            } catch (const std::exception& e) 
            {
                std::cerr << "Error parsing line: " << line << std::endl;
            }
        }
    }

    return partitionTypes;
}



//check if GPT 
bool CheckGPT(const std::vector<char>& data) {
    const size_t gptHeaderOffset = 512;
    const std::string gptSignature = "EFI PART";

    if (data.size() < gptHeaderOffset + gptSignature.size()) 
    {
        return false;
    }
    return std::equal(gptSignature.begin(), gptSignature.end(), data.begin() + gptHeaderOffset);
}
//Generaated with the help of ChatGPT 
std::string getBaseName(const std::string& filepath) {
    size_t lastSlash = filepath.find_last_of("/\\");
    return filepath.substr(lastSlash + 1);
}

//Utilized chatGPT to debug and edit the calculate hash func and put in txt files 
//# Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt
void GenMD5Hash_File(const std::string& filename, const std::vector<char>& data) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::string hashFilename = "MD5-" + getBaseName(filename) + ".txt"; 


    std::ofstream hashFile(hashFilename);
    if (!hashFile) 
    {
        std::cerr << "Error: Unable to create file " << hashFilename << std::endl;
        return;
    }
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) 
    
    {
        hashFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    hashFile.close();
    
}

void GenSHA256Hash_File(const std::string& filename, const std::vector<char>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);

    std::string hashFilename = "SHA-256-" + getBaseName(filename) + ".txt"; 
    std::ofstream hashFile(hashFilename);
    if (!hashFile) 
    
    {
        std::cerr << "Error: Unable to create file " << hashFilename << std::endl;
        return;
    }
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) 
    {
        hashFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    hashFile.close();
    
}

void GenSHA512Hash_File(const std::string& filename, const std::vector<char>& data) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    //Fiund the Hash 
    SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::string hashFilename = "SHA-512-" + getBaseName(filename) + ".txt"; 
    std::ofstream hashFile(hashFilename);
    if (!hashFile) 
    
    {
        std::cerr << "Error: Unable to create file " << hashFilename << std::endl;
        return;
    }
    //Save the hash to the file 
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) 
    {
        hashFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    hashFile.close();
  
}

//Function to check MBR psrtition and get the info and print in given format 
void MBR_Part(const std::vector<char>& data, const std::map<int, std::string>& partitionTypes, const std::vector<int>& offsets) {
    const unsigned char* mbr = reinterpret_cast<const unsigned char*>(data.data());
    std::vector<std::string> partitionInfo;
    for (int i = 0; i < 4; ++i) {
        const unsigned char* entry = mbr + 446 + (i * 16);
        
        uint8_t type = entry[4];
        uint32_t startSector = *reinterpret_cast<const uint32_t*>(entry + 8);
        uint32_t numSectors = *reinterpret_cast<const uint32_t*>(entry + 12);
        
        if (type != 0) 
        {
            std::stringstream ss;
            ss << "(" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(type) << "), "
               << (partitionTypes.count(type) ? partitionTypes.at(type) : "Unknown")
               << " , " << std::dec << startSector * 512 << ", " << numSectors * 512;  // Convert sectors to bytes
            
            partitionInfo.push_back(ss.str());
        }
    }

    // Display all partition information
    for (const auto& info : partitionInfo) {
        std::cout << info << std::endl;
    }

    // Print boot record 
    for (int i = 0; i < partitionInfo.size(); ++i) {
        if (i < offsets.size()) {
            const unsigned char* entry = mbr + 446 + (i * 16);
            uint32_t startSector = *reinterpret_cast<const uint32_t*>(entry + 8);
            uint64_t bootRecordOffset = static_cast<uint64_t>(startSector) * 512 + offsets[i];

            if (bootRecordOffset + 16 <= data.size()) {
                std::cout << "Partition number: " << (i + 1) << std::endl;
                std::cout << "16 bytes of boot record from offset " << offsets[i] << ": ";
                
                for (int j = 0; j < 16; ++j) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') 
                              << static_cast<int>(data[bootRecordOffset + j] & 0xFF) << " ";
                }
                std::cout << std::endl << "ASCII:                                    ";
                
                for (int j = 0; j < 16; ++j) {
                    char c = data[bootRecordOffset + j];
                    std::cout << (std::isprint(static_cast<unsigned char>(c)) ? c : '.') << "  ";
                }
                std::cout << std::endl;
            }
        }
        if (i < partitionInfo.size() - 1) {
            std::cout << std::endl;  
        }
    }
}

struct GPTPartition {
    char type_guid[16];
    char unique_guid[16];
    uint64_t starting_lba;
    uint64_t ending_lba;
    uint64_t attributes;
    char name[72];
};


// Similiar function to hash txt files generators but using this for ease with GPT partitions 
void GPTCalculateAndSaveHash(const std::string& filename, const std::vector<char>& data, const std::string& hashType) {
    unsigned char hash[64];  
    int hashLength;

    if (hashType == "MD5") {
        MD5(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
        hashLength = MD5_DIGEST_LENGTH;
    } else if (hashType == "SHA-256") {
        SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
        hashLength = SHA256_DIGEST_LENGTH;
    } else if (hashType == "SHA-512") {
        SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
        hashLength = SHA512_DIGEST_LENGTH;
    } else {
  
        return;
    }

    std::string hashFilename = hashType + "-" + filename + ".txt";
    std::ofstream hashFile(hashFilename);
    for (int i = 0; i < hashLength; i++) {
        hashFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    hashFile.close();
 
}

// check for any unsued gpt partitins 
bool CheckUnusedGPT(const char* guid) {
    for (int i = 0; i < 16; ++i) {
        if (guid[i] != 0) {
            return false;
        }
    }
    return true;
}

//Used chatGPT to help debug this function 
//# Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt
//Function to partse GPT partitions and print the partiton info 
void parseGPTPartitions(const std::vector<char>& data) {
    const size_t gptHeaderOffset = 512;
    const size_t partitionEntrySize = 128;
    
    uint32_t numPartitionEntries = *reinterpret_cast<const uint32_t*>(&data[gptHeaderOffset + 80]);
    uint64_t partitionEntryLBA = *reinterpret_cast<const uint64_t*>(&data[gptHeaderOffset + 72]);
    
    size_t partitionArrayOffset = partitionEntryLBA * 512;

    for (uint32_t i = 0; i < numPartitionEntries; ++i) 
    {
       
size_t currentPartitionOffset = partitionArrayOffset + (i * partitionEntrySize);

//Point at the start of partition 
const char* partitionData = &data[currentPartitionOffset];

// Ocally save the GPT partiton struct 
const GPTPartition* partition = reinterpret_cast<const GPTPartition*>(partitionData);
        if (CheckUnusedGPT(partition->type_guid)) {
            continue;
        }

        std::cout << "Partition number: " << (i + 1) << std::endl;
        std::cout << "Partition Type GUID : ";
        // byte order for GIUID 
        for (int j = 15; j >= 0; --j) 
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(partition->type_guid[j] & 0xFF);
        }
        std::cout << std::endl;
//Print LBA info
        std::cout << "Starting LBA in hex: 0x" << std::hex << partition->starting_lba << std::endl;
        std::cout << "Ending LBA in hex: 0x" << std::hex << partition->ending_lba << std::endl;
        std::cout << "Starting LBA in Decimal: " << std::dec << partition->starting_lba << std::endl;
        std::cout << "Ending LBA in Decimal: " << std::dec << partition->ending_lba << std::endl;
        std::cout << "Partition name: ";
        for (int j = 0; j < 72; j += 2) {
            if (partition->name[j] == 0 && partition->name[j+1] == 0) break;
            std::cout << partition->name[j];
        }
        std::cout << std::endl << std::endl;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " -f <image_file1> [image_file2 ...] [-o offset1 offset2 ...]" << std::endl;
        return 1;
    }

    std::vector<std::string> filePaths;
    std::vector<int> offsets;
    bool expectingOffsets = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f") {
            // Collect all files until we hit -o or end of args
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                filePaths.push_back(argv[++i]);
            }
        } else if (arg == "-o") {
            expectingOffsets = true;
        } else if (expectingOffsets) {
            try {
                offsets.push_back(std::stoi(arg));
            } catch (const std::exception& e) {
                std::cerr << "Error parsing offset: " << arg << std::endl;
            }
        }
    }

    if (filePaths.empty()) {
        std::cerr << "Error: No input files specified." << std::endl;
        return 1;
    }

    // Process each file
    for (const auto& filePath : filePaths) {
        std::cout << "\nProcessing file: " << filePath << std::endl;
        std::cout << "----------------------------------------" << std::endl;

        // Read file
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            std::cerr << "Error opening file: " << filePath << std::endl;
            continue;  // Skip to next file
        }

        std::vector<char> fileContents((std::istreambuf_iterator<char>(file)), 
                                      std::istreambuf_iterator<char>());
        file.close();

        // Calculate hashes for each file
        GenMD5Hash_File(filePath, fileContents);
        GenSHA256Hash_File(filePath, fileContents);
        GenSHA512Hash_File(filePath, fileContents);

        // Read partition types
        std::map<int, std::string> partitionTypes = readPartitionTypes("PartitionTypes.csv");

        // Process partitions
        if (CheckGPT(fileContents)) {
            std::cout << "Partition scheme: GPT" << std::endl;
            parseGPTPartitions(fileContents);
        } else {
            std::cout << "Partition scheme: MBR" << std::endl;
            MBR_Part(fileContents, partitionTypes, offsets);
        }
    }

    return 0;
}