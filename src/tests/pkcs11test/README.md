# Test tool for Official PKCS#11 Test Cases from v3.1

## Steps

TODO

### Run physical card or virtual card environment

TODO

### Run tool

TODO

### Assess results

TODO

## Infrastructure

Test cases are parse from XML notation via libxml2 library. The tool iterates over XML nodes defining tested function calls and function return values.

For calling nodes:

* node properties are parse into simple values,
* nested nodes defining structures are parsed into structures used as input arguments for tested functions.

For return values nodes:

* node properties are parse into simple values and checked or stored into internal data if needed for later use (values depends on card),
* nested nodes defining structure are checked against or stored into internal data as needed for later use.

### Tool structure

1. `pkcs11test_process.c` - main testing function with loop
  - going over XML nodes in document
  - checking that every calling node has return node following right after
  - storing internal data with values for further use
  - **maps node names to processing functions for every PKCS#11 function**
2. `pkcs11test_func.c` - processing function
  - parsing values from node properties/arguments
  - running the PKCS#1 function with specified parameter
  - checking return value
  - checking return arguments, storing them for future use if specified
3. `pkcs11test_params_parse.c` - parse for values from XML nodes into structures
  - mapping from structure name and function flag to processing function
  - high-level parsers
  - retrieving values from internal data if needed
4. `pkcs11test_prop_parse.c` - low-level parsers for base values
5. `pkcs11test_params_check.c` - test given return values from PKCS#11 functions
  - mapping from structure name and function flag to checking functions
  - high-level checkers
  - storing data into internal memory if needed
6. `pkcs11test_prop_check.c` - low-level checkers for base values
