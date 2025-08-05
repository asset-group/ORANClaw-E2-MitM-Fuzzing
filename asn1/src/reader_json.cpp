#include "E2AP-PDU-Descriptions.h"
#include "E2AP-Constants.h"
#include "rtxsrc/rtxCommon.h"
#include "rtxsrc/rtxBuffer.h"
#include "rtxsrc/rtxMemory.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cctype>
#include <iomanip>   // For std::setw and std::setfill
#include <cstring>

// Utility: Remove extraneous whitespace (such as newlines and spaces)
// outside of JSON string literals. This “compacts” the JSON so that OCTET
// string values do not pick up unwanted formatting.
std::string removeFormatting(const std::string &json) {
    std::string result;
    bool inString = false;
    for (size_t i = 0; i < json.size(); i++) {
        char c = json[i];
        if (c == '\"') {
            result.push_back(c);
            // Toggle the inString flag when a non-escaped quote is found.
            if (i == 0 || json[i - 1] != '\\')
                inString = !inString;
        }
        // Outside a string, skip any whitespace.
        else if (!inString && std::isspace(static_cast<unsigned char>(c))) {
            continue;
        }
        else {
            result.push_back(c);
        }
    }
    return result;
}

int main(int argc, char **argv) {
    OSBOOL verbose = FALSE;
    OSBOOL aligned = TRUE;
    const char* json_input = "ric_ind_dec.json";
    OSBOOL raw_output = FALSE;
    int stat;

    // Process command-line arguments.
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v"))
            verbose = TRUE;
        else if (!strcmp(argv[i], "-json"))
            json_input = argv[++i];
        else if (!strcmp(argv[i], "-raw"))
            raw_output = TRUE;
        else if (!strcmp(argv[i], "-u"))
            aligned = FALSE;
    }

    // Read the entire JSON file into a string.
    std::ifstream inFile(json_input);
    if (!inFile) {
        std::cerr << "Error opening JSON file: " << json_input << std::endl;
        return 1;
    }
    std::stringstream ss;
    ss << inFile.rdbuf();
    std::string jsonText = ss.str();

    // Remove extra whitespace (indentation, newlines, etc.) from the JSON.
    std::string compactJson = removeFormatting(jsonText);

    // Create a JSON decode buffer using the constructor that takes a pointer and length.
    // (The OSJSONDecodeBuffer does not have a default constructor.)
    OSJSONDecodeBuffer decodeBuffer(reinterpret_cast<const OSOCTET*>(compactJson.c_str()),
                                      compactJson.size());
    decodeBuffer.setDiag(verbose);

    // Decode JSON to ASN.1 structure.
    ASN1T_E2AP_PDU data;
    ASN1C_E2AP_PDU jsonDecoder(decodeBuffer, data);
    stat = jsonDecoder.Decode();
    if (stat != 0) {
        printf("Error decoding JSON\n");
        decodeBuffer.printErrorInfo();
        return stat;
    }
    if (verbose) {
        printf("JSON decode successful\n");
        jsonDecoder.Print("E2AP");
    }

    // Encode the ASN.1 structure into PER.
    ASN1PEREncodeBuffer encodeBuffer(aligned);
    encodeBuffer.setDiag(verbose);
    ASN1C_E2AP_PDU perEncoder(encodeBuffer, data);
    stat = perEncoder.Encode();
    if (stat != 0) {
        printf("Error encoding to PER\n");
        encodeBuffer.printErrorInfo();
        return stat;
    }
    if (verbose) {
        printf("PER encode successful\n");
    }

    // Retrieve the encoded PER bytes.
    const OSOCTET* encodedMsg = encodeBuffer.getMsgPtr();
    size_t encodedLen = encodeBuffer.getMsgLen();

    // Output the PER data in raw or hex format.
    if (raw_output) {
        std::cout.write(reinterpret_cast<const char*>(encodedMsg), encodedLen);
    } else {
        std::ios_base::fmtflags f(std::cout.flags());
        for (size_t i = 0; i < encodedLen; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(encodedMsg[i]);
        }
        std::cout << std::endl;
        std::cout.flags(f);
    }
 
    return 0;
}
