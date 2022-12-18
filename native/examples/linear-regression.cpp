#include "seal/seal.h"
#include <fstream>
#include <iostream>
#include <vector>
#include "examples.h"

using namespace std;
using namespace seal;

#define MAX_ENTRY 4000
#define INC_FACTOR 1000

const char *file_small = "/afs/andrew.cmu.edu/usr24/jiachend/public/medium_dataset.csv";

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
        // data->id.push_back(std::stoi(line[6]));
        // data->name.push_back(line[7]);
        data->age.push_back(std::stoi(line[8]));
        data->income.push_back(std::stoi(line[9]) / INC_FACTOR);
        data->size++;
        line = getNextLine(myfile);
    }
    myfile.close();
}

int main()
{
    data_t *data = new data_t;
    readFile(file_small, data);

    std::cout << "DATA SIZE: " << data->size << std::endl;

    auto age = data->age;
    auto income = data->income;
    auto size = data->size;

    string line, word;
    int k = 0;

    chrono::high_resolution_clock::time_point time_start, time_end;

    cout << "Setting up context. Start time" << endl;
    time_start = chrono::high_resolution_clock::now();

    // set up context
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 40));
    SEALContext context(parms);
    BatchEncoder batch_encoder(context);
    print_parameters(context);
    cout << endl;
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

    Plaintext y_cipher_plain;
    vector<int64_t> x_plain_result;
    vector<int64_t> y_plain_result;
    decryptor.decrypt(y_cipher, y_cipher_plain);
    batch_encoder.decode(x_plain, x_plain_result);
    batch_encoder.decode(y_cipher_plain, y_plain_result);

    // Debug print statement
    cout << "x_plain: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << x_plain_result[i] << " ";
    }
    cout << endl;
    cout << "y_plain: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << y_plain_result[i] << " ";
    }
    cout << endl;

    // TODO: Calculate Coefficients a and b. Need to figure out how to sum up encrypted vector in SEAL.
    cout << "Compute x^2 and relinearize:" << endl;
    Ciphertext x_square;
    evaluator.square(x_cipher, x_square);
    evaluator.relinearize_inplace(x_square, relin_keys);

    cout << "Compute xy and relinearize:" << endl;
    Ciphertext xy_cipher;
    evaluator.multiply(x_cipher, y_cipher, xy_cipher);
    evaluator.relinearize_inplace(xy_cipher, relin_keys);

    Plaintext x_square_plain;
    Plaintext xy_cipher_plain;
    vector<int64_t> x_square_result;
    vector<int64_t> xy_cipher_result;
    decryptor.decrypt(x_square, x_square_plain);
    decryptor.decrypt(xy_cipher, xy_cipher_plain);
    batch_encoder.decode(x_square_plain, x_square_result);
    batch_encoder.decode(xy_cipher_plain, xy_cipher_result);

    // Debug print statement
    cout << "x_square_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << x_square_result[i] << " ";
    }
    cout << endl;
    cout << "xy_cipher_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << xy_cipher_result[i] << " ";
    }
    cout << endl;

    cout << "before rotating" << endl;
    vector<Ciphertext> rotations_output_x(size);
    vector<Ciphertext> rotations_output_y(size);
    vector<Ciphertext> rotations_output_x2(size);
    vector<Ciphertext> rotations_output_xy(size);

    cout << "rotate" << endl;
    for (int steps = 0; steps < size; steps++)
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

    Plaintext sum_output_x_plain;
    Plaintext sum_output_y_plain;
    vector<int64_t> sum_output_x_result;
    vector<int64_t> sum_output_y_result;
    decryptor.decrypt(sum_output_x, sum_output_x_plain);
    decryptor.decrypt(sum_output_y, sum_output_y_plain);
    batch_encoder.decode(sum_output_x_plain, sum_output_x_result);
    batch_encoder.decode(sum_output_y_plain, sum_output_y_result);

    // Debug print statement
    cout << "sum_output_x_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << sum_output_x_result[i] << " ";
    }
    cout << endl;
    cout << "sum_output_y_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << sum_output_y_result[i] << " ";
    }
    cout << endl;

    Ciphertext sum_output_xy;
    evaluator.add_many(rotations_output_xy, sum_output_xy);

    Ciphertext sum_output_x2;
    evaluator.add_many(rotations_output_x2, sum_output_x2);

    Plaintext sum_output_xy_plain;
    Plaintext sum_output_x2_plain;
    vector<int64_t> sum_output_xy_result;
    vector<int64_t> sum_output_x2_result;
    decryptor.decrypt(sum_output_xy, sum_output_xy_plain);
    decryptor.decrypt(sum_output_x2, sum_output_x2_plain);
    batch_encoder.decode(sum_output_xy_plain, sum_output_xy_result);
    batch_encoder.decode(sum_output_x2_plain, sum_output_x2_result);

    // Debug print statement
    cout << "sum_output_xy_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << sum_output_xy_result[i] << " ";
    }
    cout << endl;
    cout << "sum_output_x2_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << sum_output_x2_result[i] << " ";
    }
    cout << endl;

    Ciphertext sq_sum_output_x;
    evaluator.square(sum_output_x, sq_sum_output_x);
    evaluator.relinearize_inplace(sq_sum_output_x, relin_keys);

    parms_id_type last_parms_id = sum_output_x2.parms_id();
    evaluator.mod_switch_to_inplace(sum_output_y, last_parms_id);
    evaluator.mod_switch_to_inplace(sum_output_x, last_parms_id);

    Plaintext sum_output_x_mod_plain;
    Plaintext sum_output_y_mod_plain;
    vector<int64_t> sum_output_x_mod_result;
    vector<int64_t> sum_output_y_mod_result;
    decryptor.decrypt(sum_output_x, sum_output_x_mod_plain);
    decryptor.decrypt(sum_output_y, sum_output_y_mod_plain);
    batch_encoder.decode(sum_output_x_mod_plain, sum_output_x_mod_result);
    batch_encoder.decode(sum_output_y_mod_plain, sum_output_y_mod_result);

    // Debug print statement
    cout << "sum_output_x_mod_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << sum_output_x_mod_result[i] << " ";
    }
    cout << endl;
    cout << "sum_output_y_mod_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << sum_output_y_mod_result[i] << " ";
    }
    cout << endl;

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

    Plaintext mul_output_yx2_plain;
    Plaintext mul_output_xxy_plain;
    Plaintext mul_output_xy_plain;
    vector<int64_t> mul_output_yx2_result;
    vector<int64_t> mul_output_xxy_result;
    vector<int64_t> mul_output_xy_result;
    decryptor.decrypt(mul_output_yx2, mul_output_yx2_plain);
    decryptor.decrypt(mul_output_xxy, mul_output_xxy_plain);
    decryptor.decrypt(mul_output_xy, mul_output_xy_plain);
    batch_encoder.decode(mul_output_yx2_plain, mul_output_yx2_result);
    batch_encoder.decode(mul_output_xxy_plain, mul_output_xxy_result);
    batch_encoder.decode(mul_output_xy_plain, mul_output_xy_result);

    // Debug print statement
    cout << "mul_output_yx2_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << mul_output_yx2_result[i] << " ";
    }
    cout << endl;
    cout << "mul_output_xxy_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << mul_output_xxy_result[i] << " ";
    }
    cout << endl;
    cout << "mul_output_xy_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << mul_output_xy_result[i] << " ";
    }
    cout << endl;

    Ciphertext len;
    Plaintext plain_len(uint64_to_hex_string(size));
    encryptor.encrypt(plain_len, len);

    Ciphertext len_x2;
    evaluator.multiply(sum_output_x2, len, len_x2);
    evaluator.relinearize_inplace(len_x2, relin_keys);

    Ciphertext len_xy;
    evaluator.multiply(sum_output_xy, len, len_xy);
    evaluator.relinearize_inplace(len_xy, relin_keys);

    Plaintext len_plain;
    Plaintext len_x2_plain;
    Plaintext len_xy_plain;
    vector<int64_t> len_result;
    vector<int64_t> len_x2_result;
    vector<int64_t> len_xy_result;
    decryptor.decrypt(len, len_plain);
    decryptor.decrypt(len_x2, len_x2_plain);
    decryptor.decrypt(len_xy, len_xy_plain);
    batch_encoder.decode(len_plain, len_result);
    batch_encoder.decode(len_x2_plain, len_x2_result);
    batch_encoder.decode(len_xy_plain, len_xy_result);

    // Debug print statement
    cout << "len_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << len_result[i] << " ";
    }
    cout << endl;
    cout << "len_x2_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << len_x2_result[i] << " ";
    }
    cout << endl;
    cout << "len_xy_result: ";
    for (auto i = 0; i < 10; ++i)
    {
        cout << len_xy_result[i] << " ";
    }
    cout << endl;

    Ciphertext a_top;
    Ciphertext b_top;
    Ciphertext bot;
    parms_id_type last_parms_id_final = len_x2.parms_id();
    evaluator.mod_switch_to_inplace(sq_sum_output_x, last_parms_id_final);

    cout << "sub" << endl;
    evaluator.sub(mul_output_yx2, mul_output_xxy, a_top);
    evaluator.sub(len_xy, mul_output_xy, b_top);
    evaluator.sub(len_x2, sq_sum_output_x, bot);

    Plaintext a_top_plain;
    Plaintext b_top_plain;
    Plaintext bot_plain;
    vector<int64_t> a_top_result;
    vector<int64_t> b_top_result;
    vector<int64_t> bot_result;
    decryptor.decrypt(a_top, a_top_plain);
    decryptor.decrypt(b_top, b_top_plain);
    decryptor.decrypt(bot, bot_plain);
    batch_encoder.decode(a_top_plain, a_top_result);
    batch_encoder.decode(b_top_plain, b_top_result);
    batch_encoder.decode(bot_plain, bot_result);

    cout << "a_top_result: " << a_top_result[0] << endl;
    cout << "b_top_result: " << b_top_result[0] << endl;
    cout << "bot_result: " << bot_result[0] << endl;

    double intercept = (a_top_result[0] * 1.0) / (bot_result[0] * 1.0);
    double coefficient = (b_top_result[0] * 1.0) / (bot_result[0] * 1.0);
    cout << "intercept: " << intercept << endl;
    cout << "coefficient: " << coefficient << endl;
    cout << "End time" << endl;
    time_end = chrono::high_resolution_clock::now();

    chrono::microseconds time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    return 0;
}