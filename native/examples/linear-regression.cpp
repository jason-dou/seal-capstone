#include "seal/seal.h"
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

#define MAX_ENTRY 2000
#define INC_FACTOR 1000

const char *file_small = "/afs/andrew.cmu.edu/usr24/jiachend/public/cleaned_small_user_data.csv";

typedef struct
{
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
std::vector<std::string> getNextLine(std::istream &str)
{
    std::vector<std::string> result;
    std::string line;
    std::getline(str, line);

    std::stringstream lineStream(line);
    std::string cell;

    while (std::getline(lineStream, cell, ','))
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
void readFile(const char *filename, data_t *data)
{
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
    while (line.size() == fields && data->size < MAX_ENTRY)
    {
        data->id.push_back(std::stoi(line[0]));
        data->name.push_back(line[1]);
        data->age.push_back(std::stoi(line[2]));
        data->income.push_back(std::stoi(line[3]) / INC_FACTOR);
        data->size++;
        line = getNextLine(myfile);
    }
    myfile.close();
}

/*
Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
*/
string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

int main()
{
    data_t *data = new data_t;
    readFile(file_small, data);

    std::cout << "DATA SIZE: " << data->size << std::endl;

    vector<int64_t> age = data->age;
    vector<int64_t> income = data->income;
    string line, word;
    int k = 0;

    cout << "Setting up context" << endl;
    // set up context
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    BatchEncoder batch_encoder(context);

    // generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // encrypt
    Plaintext x_plain;
    Ciphertext x_cipher;
    batch_encoder.encode(age, x_plain);
    encryptor.encrypt(x_plain, x_cipher);
    Plaintext y_plain;
    Ciphertext y_cipher;
    batch_encoder.encode(income, y_plain);
    encryptor.encrypt(y_plain, y_cipher);

    // TODO: Calculate Coefficients a and b. Need to figure out how to sum up encrypted vector in SEAL.
    cout << "Compute x^2 and relinearize:" << endl;
    Ciphertext x_square;
    evaluator.square(x_cipher, x_square);
    evaluator.relinearize_inplace(x_square, relin_keys);

    cout << "Compute xy and relinearize:" << endl;
    Ciphertext xy_cipher;
    evaluator.multiply(x_cipher, y_cipher, xy_cipher);
    evaluator.relinearize_inplace(xy_cipher, relin_keys);

    cout << "before rotating" << endl;
    int data_size = age.size();
    vector<Ciphertext> rotations_output_x(data_size);
    vector<Ciphertext> rotations_output_y(data_size);
    vector<Ciphertext> rotations_output_x2(data_size);
    vector<Ciphertext> rotations_output_xy(data_size);

    cout << "rotate" << endl;
    for (int steps = 0; steps < data_size; steps++)
    {
        evaluator.rotate_rows(x_cipher, steps, galois_keys, rotations_output_x[steps]);
        evaluator.rotate_rows(y_cipher, steps, galois_keys, rotations_output_y[steps]);
        evaluator.rotate_rows(x_square, steps, galois_keys, rotations_output_x2[steps]);
        evaluator.rotate_rows(xy_cipher, steps, galois_keys, rotations_output_xy[steps]);
    }
    cout << "rotation over" << endl;

    Ciphertext sum_output_x;
    evaluator.add_many(rotations_output_x, sum_output_x);

    Ciphertext sum_output_y;
    evaluator.add_many(rotations_output_y, sum_output_y);

    Ciphertext sum_output_xy;
    evaluator.add_many(rotations_output_xy, sum_output_xy);

    Ciphertext sum_output_x2;
    evaluator.add_many(rotations_output_x2, sum_output_x2);

    Ciphertext sq_sum_output_x;
    evaluator.square(sum_output_x, sq_sum_output_x);
    evaluator.relinearize_inplace(sq_sum_output_x, relin_keys);

    parms_id_type last_parms_id = sum_output_x2.parms_id();
    evaluator.mod_switch_to_inplace(sum_output_y, last_parms_id);
    evaluator.mod_switch_to_inplace(sum_output_x, last_parms_id);

    cout << "multiply" << endl;
    Ciphertext mul_output_yx2;
    evaluator.multiply(sum_output_x2, sum_output_y, mul_output_yx2);
    evaluator.relinearize_inplace(mul_output_yx2, relin_keys);

    Ciphertext mul_output_xxy;
    evaluator.multiply(sum_output_x, sum_output_xy, mul_output_xxy);
    evaluator.relinearize_inplace(mul_output_xxy, relin_keys);

    Ciphertext mul_output_xy;
    evaluator.multiply(sum_output_x, sum_output_y, mul_output_xy);
    evaluator.relinearize_inplace(mul_output_xy, relin_keys);

    Ciphertext len;
    Plaintext plain_len(uint64_to_hex_string(data_size));
    encryptor.encrypt(plain_len, len);

    Ciphertext mul_1;
    evaluator.multiply(sum_output_x2, len, mul_1);
    evaluator.relinearize_inplace(mul_1, relin_keys);

    Ciphertext mul_2;
    evaluator.multiply(sum_output_xy, len, mul_2);
    evaluator.relinearize_inplace(mul_2, relin_keys);

    Ciphertext res1;
    Ciphertext res2;
    Ciphertext res3;
    parms_id_type last_parms_id_final = mul_1.parms_id();
    evaluator.mod_switch_to_inplace(sq_sum_output_x, last_parms_id_final);

    cout << "sub" << endl;
    evaluator.sub(mul_output_yx2, mul_output_xxy, res1);
    evaluator.sub(mul_2, mul_output_xy, res2);
    evaluator.sub(mul_1, sq_sum_output_x, res3);

    cout << "result" << endl;
    Plaintext result1, result2, result3;
    decryptor.decrypt(res1, result1);
    decryptor.decrypt(res2, result2);
    decryptor.decrypt(res3, result3);

    vector<int64_t> finalresult1;
    vector<int64_t> finalresult2;
    vector<int64_t> finalresult3;
    batch_encoder.decode(result1, finalresult1);
    batch_encoder.decode(result2, finalresult2);
    batch_encoder.decode(result3, finalresult3);

    cout << result1[0] << endl;
    cout << result2[0] << endl;
    cout << result3[0] << endl;
    return 0;
}