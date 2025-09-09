# TODO list

## DSA

### List
- Copy and rename current array implementation to list

### Array
- Change to sequential array


## Scanner

### JS scanning
- EOI based on the input length

### String scanning
- properly support scanning from string
- add support for YYFILL
  - streams
  - change EOI


## Parser
- add some function that will parse string and return the value
  - wrapping all the logic to make usage simple
- test locations support
- change it to push parser (stream support)


## IO
- fix printf to not use standard malloc that is used by vsnprintf
- rename read hook to fill
- create a new hook read that will copy data to the buffer
- suppress valgrind errors without using calloc for new buffer
- test various allocation using valgrind


## Encoder

### Double encoding
- use custom dtoa function for double serialization
  - allows selection of custom precision and mode

### String encoding
- flag for escaping slashes
- utf8 validation
- unicode escaping
- marked buffering


## Pointer

- pointer parser method - it will save only the pointer result - the rest will be just validated


## Schema

### Parsing

- default support
- metadata api so things like description, title, examples, $comment and others can be somehow used
- definitions ($defs) pre-parsing to speed up dynamic refs
- draft diffs detailed review (from release notes)
- formats
- selected parsing only of the elements that are in the schema instead of checking all fields
- update and extend unit tests

### References

- external data fetching
  - some sort of registries when local schema with different ids can be stored
  - generic client interface
  - maybe curl implementation of the interface for optional network fetching
    - this is, however, discouraged in the schema spec

### Validation

- default keyword validation and test
  - double check that it really works with if / then / else test
- error collection for multiple errors and related helper functions
  - this is important for getting correct errors in if / then / else (see TODO in jso_schema_validation_result_propagate) 
- advance test for if / then / else
- advance test for dependencies
- add initial integration test for draft 2019-09
- add and test full support for dependentSchemas and dependentRequired
- add support for unevaluatedProperties
- add support for unevaluatedItems
- add support for maxContains
- look into $anchor support and other core vocabulary changes for 2019-09
- support for draft 2020-12
- early exit for arrays and object
- propagation should happen only in reverse iteration
  - add special tests for this
- validation method for multiple validators
- introduce a simple validator for schemas without composition
  - this should be significantly faster
- unit tests
- string unicode length for correct validation

### Errors

- function for error description by the code
- support collecting of multiple errors

## CLI

- schema support
- generate help message
  - extend `jso_cli_param` with description
- add support for grouping of short arguments
- allow setting of output stream (stdout and stderr)
- allow stream input (stdin - using jso in pipe)
  - it requires parser stream support

## Testing

### Unit
- extend coverage

### Integration
- create some common place for tests that are the same between drafts (sharing code)

## Build
- test - check
  - differentiate between integration and unit tests - targets to run only one
  - gcov support
- pkg
  - version check
- bison
  - autoconf version check including removal of `-y` flag for POSIX
  - remove Makefile AM rule (use AC)
  - jso_parser.tab.h - prerequisite (build error when it's not created)
  - do not emulate POSIX Yacc (do not use -y option added by default)
- parser debug
  - use option --enable-parser-debug
  - set YYDEBUG macro to 1 if enabled, otherwise 0
- re2c
  - autoconf version check
  - try to replace Makefile AM rule with AC
- optional generating of files (re2c and bison)
  - included generated files that will be used if not checked
- autogen.sh
  - check for autoconf, automake, libtool (libtoolize)
- add CMake support mainly for Windows and possibly to eventually replace autotools

## Documentation
- document source using doxygent comments
- MarkDown documentation (GitHub)
  - document jso executable
  - document exported API
  - add some examples
