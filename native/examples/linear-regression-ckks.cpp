#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "examples.h"

using namespace std;
using namespace seal;

int main()
{
    vector<string> row;
    vector<double> age;
    vector<double> salary;
    string line, word;
    int k = 0;
    fstream file("medium_dataset.csv", ios::in);
    if (file.is_open())
    {
        // Skip csv header
        getline(file, line);

        while (getline(file, line) && k < 10)
        {
            row.clear();

            stringstream str(line);
            int i = 0;
            while (getline(str, word, ','))
            {
                cout << word << endl;
                if (i == 8)
                    age.push_back(stod(word.c_str()));
                if (i == 9)
                    salary.push_back(stod(word.c_str()));
                i = i + 1;
            }
            k = k + 1;
        }
    }
    else
        cout << "Could not open the file\n";

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);

    SEALContext context(parms);

    print_parameters(context);
    cout << endl;
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    Plaintext x_plain;
    Plaintext y_plain;
    encoder.encode(age, scale, x_plain);
    encoder.encode(salary, scale, y_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);
    Ciphertext y1_encrypted;
    encryptor.encrypt(y_plain, y1_encrypted);

    Ciphertext x3_encrypted;
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x3_encrypted);

    Ciphertext xy_encrypted;
    evaluator.multiply(x1_encrypted, y1_encrypted, xy_encrypted);
    evaluator.relinearize_inplace(xy_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(xy_encrypted);

    cout << age.size();
    vector<Ciphertext> rotations_output_x(age.size());
    vector<Ciphertext> rotations_output_y(age.size());
    vector<Ciphertext> rotations_output_x2(age.size());
    vector<Ciphertext> rotations_output_xy(age.size());

    cout << "rotate";
    for (int steps = 0; steps < age.size(); steps++)
    {
        evaluator.rotate_vector(x1_encrypted, steps, gal_keys, rotations_output_x[steps]);
        evaluator.rotate_vector(y1_encrypted, steps, gal_keys, rotations_output_y[steps]);
        evaluator.rotate_vector(x3_encrypted, steps, gal_keys, rotations_output_x2[steps]);
        evaluator.rotate_vector(xy_encrypted, steps, gal_keys, rotations_output_xy[steps]);
    }

    cout << "rotation over" << endl;

    Plaintext plain_result_x;

    Ciphertext sum_output;
    evaluator.add_many(rotations_output_x, sum_output);

    Ciphertext sum_output_y;
    evaluator.add_many(rotations_output_y, sum_output_y);

    Ciphertext sum_output_xy;
    evaluator.add_many(rotations_output_xy, sum_output_xy);

    Ciphertext sum_output_x2;
    evaluator.add_many(rotations_output_x2, sum_output_x2);

    Ciphertext sqOfsum;
    evaluator.square(sum_output, sqOfsum);
    evaluator.relinearize_inplace(sqOfsum, relin_keys);
    evaluator.rescale_to_next_inplace(sqOfsum);

    Ciphertext mul_output_yx2;

    parms_id_type last_parms_id = sum_output_x2.parms_id();

    evaluator.mod_switch_to_inplace(sum_output_y, last_parms_id);

    evaluator.multiply(sum_output_x2, sum_output_y, mul_output_yx2);
    evaluator.relinearize_inplace(mul_output_yx2, relin_keys);
    evaluator.rescale_to_next_inplace(mul_output_yx2);

    Ciphertext mul_output_xxy;
    evaluator.mod_switch_to_inplace(sum_output, last_parms_id);
    // evaluator.mod_switch_to_inplace(sum_output_xy, last_parms_id);

    cout << "multiply" << endl;
    cout << sum_output_xy.parms_id() << endl;
    cout << sum_output.parms_id() << endl;

    evaluator.multiply(sum_output, sum_output_xy, mul_output_xxy);
    evaluator.relinearize_inplace(mul_output_xxy, relin_keys);
    evaluator.rescale_to_next_inplace(mul_output_xxy);

    Ciphertext mul_output_xy;

    evaluator.multiply(sum_output, sum_output_y, mul_output_xy);
    evaluator.relinearize_inplace(mul_output_xy, relin_keys);
    evaluator.rescale_to_next_inplace(mul_output_xy);

    Ciphertext len;
    Plaintext plain_len;
    double datasize = static_cast<double>(age.size());
    encoder.encode(datasize, scale, plain_len);
    encryptor.encrypt(plain_len, len);

    cout << endl;

    evaluator.mod_switch_to_inplace(len, last_parms_id);

    Ciphertext mul_1;
    evaluator.multiply(sum_output_x2, len, mul_1);
    evaluator.relinearize_inplace(mul_1, relin_keys);
    evaluator.rescale_to_next_inplace(mul_1);

    Ciphertext mul_2;
    evaluator.multiply(sum_output_xy, len, mul_2);
    evaluator.relinearize_inplace(mul_2, relin_keys);
    evaluator.rescale_to_next_inplace(mul_2);

    Ciphertext res1;
    Ciphertext res2;
    Ciphertext res3;

    parms_id_type last_parms_id_finl = mul_1.parms_id();

    evaluator.mod_switch_to_inplace(sqOfsum, last_parms_id_finl);

    cout << mul_output_yx2.parms_id() << endl;
    cout << mul_output_xxy.parms_id() << endl;
    cout << mul_2.parms_id() << endl;
    cout << mul_output_xy.parms_id() << endl;
    cout << mul_1.parms_id() << endl;
    cout << sqOfsum.parms_id() << endl;

    evaluator.sub(mul_output_yx2, mul_output_xxy, res1);

    mul_1.scale() = pow(2.0, 40);
    sqOfsum.scale() = pow(2.0, 40);
    evaluator.sub(mul_1, sqOfsum, res3);
    mul_2.scale() = pow(2.0, 40);
    mul_output_xy.scale() = pow(2.0, 40);
    evaluator.sub(mul_2, mul_output_xy, res2);

    Plaintext result1, result2, result3;
    decryptor.decrypt(res1, result1);
    decryptor.decrypt(res2, result2);
    decryptor.decrypt(res3, result3);

    vector<double> finalresult1;
    vector<double> finalresult2;
    vector<double> finalresult3;
    encoder.decode(result1, finalresult1);
    encoder.decode(result2, finalresult2);
    encoder.decode(result3, finalresult3);

    cout << result1[0] << endl;
    cout << result2[0] << endl;
    cout << result3[0] << endl;
    return 0;
}