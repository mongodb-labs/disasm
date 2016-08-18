## Interactive Disassembler GUI

Before running:

1. Install [Capstone](http://www.capstone-engine.org/download.html)
2. `pip install -r requirements.txt`
2. Copy `config.template.py` into a file called `config.py`, and replace the upload path and source code directory path in `config.py` with the appropriate relative paths on your machine.

There is optional IACA integration; to use it, you must first download IACA from [Intel's website](https://software.intel.com/en-us/articles/intel-architecture-code-analyzer-download) and update variables in your config.py accordingly.

To run:
```python
python run.py
python run.py -f <file(s)>
```

`run.py` uses gunicorn for speed and robustness. 

---

#### Using PyPy for speed
[PyPy](http://pypy.org/) is an alternative implementation of python that provides a considerable speedup. To use it, there is a little more setup involved.

1. `pip_pypy install -r requirements.pypy.txt` (regular pip doesn't install to a directory that pypy can find)
2. Ensure that you have either `c++filt` or `gc++filt` on your machine/in your `$PATH` (The demangler library we use does not work with pypy. If you know of a python demangler library that can run on pypy, let us know!)

