[![Wyeomyia smithii](https://github.com/okeuday/pest/raw/master/images/320px-Wyeomyia_smithii.jpg)](https://en.wikipedia.org/wiki/Mosquito#Lifecycle)

Primitive Erlang Security Tool (PEST)
-------------------------------------

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
      -r              Recursively search directories
      -s SEVERITY     Set the minimum severity to use when reporting problems
                      (default is 50)
      -v              Verbose output (set the minimum severity to 0)
    
Please feel free to contribute, to add security problems to the scan
(just insert into the [list of checks](https://github.com/okeuday/pest/blob/3b63e573daa458c68f23a717a4c2168a2e430da3/pest.erl#L122-L185)).

Test
----

To have pest.erl check itself, use:

    ./pest.erl -v -c ./pest.erl

Author
------

Michael Truog (mjtruog [at] gmail (dot) com)

License
-------

BSD

