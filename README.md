## Interactive Disassembler GUI

Before running:

1. Install [Capstone](http://www.capstone-engine.org/download.html)
2. Replace the upload path and source code directory path in `config.py` with the appropriate relative paths on your machine.

There is optional IACA integration; to use it, you must first download IACA from [Intel's website](https://software.intel.com/en-us/articles/intel-architecture-code-analyzer-download) and update variables in your config.py accordingly.

To run:
```python
python run.py
```

`run.py` uses gunicorn for speed and robustness. If you don't want to use gunicorn, you can use `python app.py`.

### Known Bugs
function search breaks if you have unmatched parens
