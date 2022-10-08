#include <iostream>
#include <fstream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

#define MAX_ENTRY 2000
#define INC_FACTOR 10

const char* file_small = "/afs/andrew.cmu.edu/usr24/jiachend/public/cleaned_small_user_data.csv";

typedef struct {
    std::vector<int> id;
    std::vector<std::string> name;
    std::vector<int64_t> age;
    std::vector<int64_t> income;
    size_t size;
} data_t;

/**
 * @brief Get the Next Line And Split Into Tokens
 * 
 * https://stackoverflow.com/questions/1120140/how-can-i-read-and-parse-csv-files-in-c
 * 
 * @param str File Stream
 * @return std::vector<std::string>
 */
std::vector<std::string> getNextLine(std::istream& str)
{
    std::vector<std::string>   result;
    std::string                line;
    std::getline(str,line);

    std::stringstream          lineStream(line);
    std::string                cell;

    while(std::getline(lineStream,cell, ','))
    {
        result.push_back(cell);
    }
    // This checks for a trailing comma with no data after it.
    if (!lineStream && cell.empty())
    {
        // If there was a trailing comma then add an empty element.
        result.push_back("");
    }
    return result;
}

/**
 * @brief Read the age-income data file
 * 
 * @param filename The name of the file
 * @param data Structure of data to be filled in.
 */
void readFile(const char* filename, data_t *data) {
    std::ifstream myfile;
    myfile.open(filename);
    auto line = getNextLine(myfile);
    size_t fields = line.size();
    line = getNextLine(myfile);
    data->size = 0;
    data->id.clear();
    data->name.clear();
    data->age.clear();
    data->income.clear();
    while(line.size() == fields && data->size < MAX_ENTRY) {
        data->id.push_back(std::stoi(line[0]));
        data->name.push_back(line[1]);
        data->age.push_back(std::stoi(line[2]));
        data->income.push_back(std::stoi(line[3]) / INC_FACTOR);
        data->size++;
        line = getNextLine(myfile);
    }
    myfile.close();
}

int main() {
    data_t *data = new data_t;
    readFile(file_small, data);

    std::cout << "DATA SIZE: " << data->size << std::endl;

    EncryptionParameters parms(scheme_type::bfv);
    return 0;
}