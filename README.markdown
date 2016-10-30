[![Wyeomyia smithii](https://github.com/okeuday/pest/raw/master/images/320px-Wyeomyia_smithii.jpg)](https://en.wikipedia.org/wiki/Mosquito#Lifecycle)

Primitive Erlang Security Tool (PEST)
-------------------------------------

[![Build Status](https://secure.travis-ci.org/okeuday/pest.png?branch=master)](http://travis-ci.org/okeuday/pest)
[![hex.pm version](https://img.shields.io/hexpm/v/pest.svg)](https://hex.pm/packages/pest)

Do a basic scan of Erlang source code and report any function calls that may
cause Erlang source code to be insecure.

The tool is provided in the form of an escript (an Erlang script) which may
also be used as a module, however, module usage currently requires changing
the first line of the file to not have a `#` character
(can insert `%` to comment it out, there is a bug filed about this problem at
 [ERL-289](https://bugs.erlang.org/browse/ERL-289)).  Usage of the script
is provided with the `-h` command line argument, with the output shown below:

    Usage pest.erl [OPTION] [FILES] [DIRECTORIES]
    
      -b              Only process beam files recursively
      -c              Perform internal consistency checks
      -e              Only process source files recursively
      -h              List available command line flags
      -m APPLICATION  Display a list of modules in an Erlang/OTP application
      -r              Recursively search directories
      -s SEVERITY     Set the minimum severity to use when reporting problems
                      (default is 50)
      -v              Verbose output (set the minimum severity to 0)
      -V [COMPONENT]  Print version information
                      (valid components are: pest, crypto)
    
Erlang/OTP version 19.0 and higher is required.
If beam files are used, they must have been compiled with the `debug_info`
option to provide the `abstract_code` used by pest.erl.  However, pest.erl
also consumes Erlang source code, including Erlang source escript files.
If beam files are available, it is best to use the beam files with pest.erl
due to how the Erlang compiler preprocessor and optimizations can influence
function calls.

Please feel free to contribute!  To add security problems to the scan
insert information into the [list of checks](https://github.com/okeuday/pest/blob/master/pest.erl#L122-L223).

Test
----

To have pest.erl check itself, use:

    ./pest.erl -v -c ./pest.erl

To check version information related to Erlang/OTP crypto, use:

    ./pest.erl -V crypto

Author
------

Michael Truog (mjtruog [at] gmail (dot) com)

License
-------

BSD

