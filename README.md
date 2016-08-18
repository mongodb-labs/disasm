Interactive Disassembler GUI
============================

* [Before running](#before-running)
    * [IACA](#iaca)
    * [Gunicorn](#gunicorn)
    * [Pypy](#pypy)
* [Running](#running)
    * [Options](#options)
* [About](#about)
* [Features](#features)
    * [Disassembly](#disassembly)
    * [Source code stack trace](#source-code-stack-trace-)
    * [IACA integration](#iaca-integration)
    * [Register contents](#register-contents-)
    * [Register tracking](#register-tracking-)
    * [Flags read/written](#flags-readwritten)
    * [Jump table resolution](#jump-table-resolution)
    * [Rip-relative address resolution and interpretation](#rip-relative-address-resolution-and-interpretation)
    * [Type analysis](#type-analysis-)
    * [Jumping](#jumping)
    * [Number conversion](#number-conversion)
    * [Instruction documentation](#instruction-documentation)
    * [File upload](#file-upload)
    * [NOP byte size](#nop-byte-size)
    * [Keyboard shortcuts](#keyboard-shortcuts)
        * [Function search](#function-search)
        * [Disassembly](#disassembly-1)
            * [Analysis window open](#analysis-window-open)
* [Bugs](#bugs)
* [Contributors](#contributors)
* [License](#license)

Before running
-----------------

1. Install [Capstone](http://www.capstone-engine.org/download.html)
2. Install the dependencies
    * `$ pip install -r requirements.txt --ignore-installed`
3. Replace the upload path and source code directory path in `config.py` with the appropriate relative paths on your machine.

### IACA

There is optional IACA integration. To use it, you must first download IACA from [Intel's website](https://software.intel.com/en-us/articles/intel-architecture-code-analyzer-download) and update variables in your config.py accordingly.

### Gunicorn

[Gunicorn](http://gunicorn.org/) is a fast and robust server, and requires little setup. It's also far more reliable; there are known issues with using Werkzeug (the default Flask server) that cause that server to crash if you send too many requests in a short amount of time.

Run `pip install gunicorn` to install it.

### PyPy

[PyPy](http://pypy.org/) is an alternative implementation of python that provides a considerable speedup. To use it, there is a little more setup involved.

1. Setup the requirements for pypy using either of the following:
    * Use pip_pypy
        * `pip_pypy install -r requirements.pypy.txt` (regular pip doesn't install to a directory that pypy can find)
    * Use virtualenv and pip
        * `mkvirtualenv -p /path/to/pypy name-of-virtualenv`
        * pip install -r requirements.txt
2. Ensure that you have either `c++filt` or `gc++filt` on your machine/in your `$PATH` (The demangler library we use does not work with pypy. If you know of a python demangler library that can run on pypy, let us know!)

Running
-------

The simplest way to run the application is the following way:

```python
python app/app.py
```

This approach does not require you to download or install anything more than the dependencies listed in requirements.txt, but it is also the slowest and least reliable.

If Gunicorn is installed, you can start the application by running the following:

```python
python run.py
python run.py -f <file(s)>
```

<<<<<<< f48072ddc62aa0b7be3fdebe42d3a5d8284c0928
`run.py` uses gunicorn for speed and robustness. 

---

#### Using PyPy for speed
[PyPy](http://pypy.org/) is an alternative implementation of python that provides a considerable speedup. To use it, there is a little more setup involved.

1. `pip_pypy install -r requirements.pypy.txt` (regular pip doesn't install to a directory that pypy can find)
2. Ensure that you have either `c++filt` or `gc++filt` on your machine/in your `$PATH` (The demangler library we use does not work with pypy. If you know of a python demangler library that can run on pypy, let us know!)
=======
If Pypy is installed, then you can run the application by running pypy instead of python:

```python
pypy app/app.py
```

You can also combine Gunicorn and Pypy to form the best experience:

```python
pypy run.py
```

### Options

* -f <file(s)>, --files <file(s)>
    * File(s) that you want to appear on the homepage to disassemble.

About
-----

Disasm is a web application written in Flask. It allows you to disassemble ELF files that have been assembled as Intel x86 assembly. The assembly and analysis can be displayed in a browser so that you can click around and interact with it.

Features
--------

Features marked with an asterisk (*) require that the .dwarf_info and .dwarf_aranges sections be defined in order to use it.

### Disassembly

The main feature of the application, an Intel x86 ELF executable can be disassembled into x86 assembly and displayed in the browser.

### Source code stack trace *

After selecting a line of assembly, the source code that corresponds to it can be displayed, as well as the full stack trace of function calls that refer to it.

Note: This feature requires that the source directory of the code that compiled into this executable be defined in config.py.

![source code stack trace](screenshots/stack-trace.png "Example of source code stack trace")

### IACA integration

A sequence of instructions can be analyzed by Intel IACA.

Note: In order to use this feature, you must first download IACA from [Intel's website](https://software.intel.com/en-us/articles/intel-architecture-code-analyzer-download) and update variables in your config.py accordingly.

![intel iaca integration](screenshots/iaca.gif "Using IACA to determine the throughput of a set of instructions")

### Register contents *

Whenever possible, the contents of a register will be displayed, including the object's member that is being pointed to if a valid offset is given.

![register tracking](screenshots/register-tracking.png "Determine the contents of a register")

### Register tracking *

Observe which instructions read and/or write to a particular register. To activate this feature, right click the desired register and select the appropriate option.

![registers written to and read from](screenshots/relevant-registers.png "Display all of the instructions that write to or read from this register")

### Flags read/written

Instructions that write to a flag(s) will display a white flag next to the mnemonic. Instructions that read from a flag(s) will display a black flag next to the mnemonic. Hovering over the flag will display which flags are read to/written from in this operation.

![flags written to and read from](screenshots/relevant-flags.png "Display all of the flags that are written to or read from")

### Jump table resolution 

Jump tables are parsed. Clicking on the first instruction in a jump table sequence will display a the table the mapping between value in rdi (the condition) and the address to jump to. Clicking on one of these addresses will allow you to jump to this instruction as well.

![jump table parsing](screenshots/jump-table.png "Display the information relevant to the detected jump table")

### Rip-relative address resolution and interpretation

A rip-relative adddress (e.g, "rip + 0x129d866") can be resolved into a single address by right clicking on that part of the instruction. The value at this address can also be read from the file as an 8/16/32/64-bit signed decimal/unsigned decimal/hexadecimal/binary number, single/double precision floating point number, or null-terminated C String (up to 128 bytes).

![rip relative resolution and interpretation](screenshots/rip-relative.gif "Resolving the RIP-relative address and interpreting the data at that address")

### Type analysis *

You can search for a type that is defined in this file in order to obtain obtain in-depth information about this type, including its size, subtype, and member variables. When displaying member variables, you can also see their types, their offsets, and their name.

![type analysis](screenshots/type-analysis.gif "Obtaining information about a given type")

### Jumping

Clicking on the address of a jump or call instruction will allow you to jump to the address.

![jumping](screenshots/jumping.gif "Following instruction jumps")

### Number conversion

By right clicking on an immediate value, you can convert it to/from decimal (signed and unsigned), hexadecimal, and binary. If the number is less than 128 in unsigned decimal, then it can also be converted to ASCII.

![number conversion](screenshots/number-conversion.gif "Converting numbers")

### Instruction documentation

Hovering over an instruction mnemonic will display a short explaination of what it does. Clicking on an instruction mnemonic will display an in-depth explaination.

![short description](screenshots/short-description.png "Short description of what the instruction does")

![full description](screenshots/full-description.png "Full documentation for the instruction")

### File upload

When a file is uploaded, it will be stored on the server for quicker lookup later. These files can also be deleted.

![file upload](screenshots/file-upload.png "Display the list of files previously uploaded")

### NOP byte size

There are various different NOP instructions, each of which is encoded as a different operation, and each with a different size. Instead of displaying the operation (which is essentially meaningless), the size of the NOP will be displayed.

![NOP byte size](screenshots/nop-byte-size.png "Display the size of the NOP instruction")

### Keyboard shortcuts

#### Function search

* Up/down
    * Navigate through the list of functions
* Enter
    * Disassemble the currently selected function
* ?
    * Display the help menu

#### Disassembly

* Up/down 
    * Navigate through the instructions
* Right Arrow
    * On jmp/call
        * Go to target address
    * On ret
        * Return to the calling function (only available if this function was reached by entering going through a call instruction)
* Left Arrow
    * Undo previous jump/call (if applicable)
* Enter
    * Open the analysis window relevant to this instruction

##### Analysis window open

* Shift + up/down
    * Go up/down the function stack
* Tab
    * Cycle through the analysis tabs
* Escape
    * Close the analysis window

Bugs
----

No known bugs.

If any bugs are found, please contact `hareldan95@gmail.com` or `dorothchen@gmail.com` with as much of the following information as possible:

* Version of python being run
* Source code language and version
* A link to download the executable, along with the name of the function that prodeced the bug.
* If an error/exception was raised, then the full stack trace of the error/exception.
* The browser and version of the browser being used.
* Anything else you think might be relevant.

Contributors
------------

* Dorothy Chen
* Dan Harel

License
-------

Copyright 2016 MongoDB Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0
>>>>>>> readme
>>>>>>> Updated README

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.