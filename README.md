# Microsoft SEAL

This repo is forked from the main Microsoft SEAL repo and contains the linear regrerssion program using Microsoft SEAL BFV Scheme. The main repo can be found at https://github.com/microsoft/SEAL

The BFV program for linear regression is at https://github.com/jason-dou/seal-capstone/blob/main/native/examples/linear-regression.cpp

To run the Microsoft SEAL BFV linear regression program:

1. Clone the repo from github
   - `git clone https://github.com/jason-dou/seal-capstone.git`
1. `cd seal-capstone`
1. `cmake -S . -B build -DSEAL_BUILD_EXAMPLES=ON`
1. `cmake --build build`
1. To run the programs:
   - BFV: `./build/bin/linear-regression-bfv`
   - CKKS: `./build/bin/linear-regression-ckks`

To run an updated version the linear-regression with new changes:

1. `cmake --build build`
1. To run the programs:
   - BFV: `./build/bin/linear-regression-bfv`
   - CKKS: `./build/bin/linear-regression-ckks`
