# Copyright 2016 MongoDB Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, datetime, json
from flask import Flask, render_template, request, redirect, url_for, jsonify, g
from flask_assets import Environment, Bundle
from werkzeug.utils import secure_filename
import hurry.filesize

import disassemble as disasm
import iaca
from function_store import storeFunctions, getFunctions, getFunctionsBySubstring, hasStoredFunctions
from executable import *
import executable
from disassemble import disasm, jsonify_capstone
from binascii import unhexlify

app = Flask(__name__)
app.config.from_pyfile('config.py')

assets = Environment(app)

# relative to static dir
index_scss = Bundle(
    'scss/index.scss', 
    filters='pyscss', 
    output='generated/index_all.css')
assets.register('index_css', index_scss)

functions_scss = Bundle(
    'scss/general.scss',
    'scss/functions.scss', 
    filters='pyscss', 
    output='generated/functions_all.css')
assets.register('functions_css', functions_scss)

disassemble_scss = Bundle(
    'scss/general.scss',
    'scss/disassemble.scss',
    filters='pyscss', 
    output='generated/disassemble_all.css')
assets.register('disassemble_css', disassemble_scss)

# Javascript files that are used in index.jinja.tml
js_index = Bundle(
    'js/index.js',
    'js/index_shortcuts.js',
    output='generated/index_all.js')
assets.register('js_index', js_index)

# Javascript files that are used in functions.jinja.html
js_functions = Bundle(
    'js/functions.js',
    'js/functions_shortcuts.js',
    output='generated/functions_all.js')
assets.register('js_functions', js_functions)

# Javascript files that are used in disassemble.jinja.html
js_disassemble = Bundle(
    'js/disassemble.js', 
    'js/biginteger.js',
    'js/functions.js',
    'js/disassembly_analysis.js',
    'js/instruction_events.js',
    'js/number_conversion.js',
    'js/jquery.contextMenu.js',
    'js/jquery.contextMenu.js',
    'js/jquery.ui.position.js',
    'js/highlight.pack.js',
    'js/tipr.js',
    'js/register_info.js',
    'js/disassemble_shortcuts.js',
    output='generated/disassemble_all.js')
assets.register('js_disassemble', js_disassemble)

# Javascript files that are used on all pages.
js_global = Bundle(
    'js/keypress.js',
    'js/rivets.js',
    'js/global_shortcuts.js',
    'js/jquery.colorbox-min.js',
    output='generated/global_all.js')
assets.register('js_global', js_global)

# home and upload
@app.route('/', methods=['GET', 'POST'])
def index():
    if not os.path.exists(app.config['UPLOAD_DIR']):
        os.makedirs(app.config['UPLOAD_DIR'])
    # uploading new file
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_DIR'], filename))
        return redirect(url_for('functions', filename=filename))
    else:
        res = {}
        files = os.listdir(app.config['UPLOAD_DIR'])
        # display file info
        for file in files:
            t = os.path.getmtime(app.config['UPLOAD_DIR'] + file)
            timestamp = datetime.datetime.fromtimestamp(t)
            size = os.path.getsize(app.config['UPLOAD_DIR'] + file)
            res[file] = [hurry.filesize.size(size), timestamp]
        
        return render_template("index.jinja.html", files=res)

def loadExec(filename):
    path = app.config['UPLOAD_DIR'] + filename
    f = open(path, 'rb')
    a = get_executable(f)
    executable.ex = a
    print "Done loading the executable"

## determine which kind of executable
def get_executable(f):
    if Executable.isElf(f):
        return ElfExecutable(f)
    elif Executable.isMacho(f):
        return MachoExecutable(f)
    else:
        raise Exception("Couldn't find executable format")

def load_functions(filename):
    if not executable.ex:
        loadExec(filename)
    functions = executable.ex.get_all_functions()
    storeFunctions(functions)

@app.route('/functions', methods=['GET'])
def functions():
    load_functions(request.args['filename'])
    return render_template('functions.jinja.html', filename=request.args['filename'])   

# expects "filename", "st_value", "file_offset", "size", "func_name"
@app.route('/disasm_function', methods=['GET'])
def disasm_function():
    # initially empty page; load all info via ajax
    return render_template("disassemble.jinja.html", 
        filename=request.args['filename'], 
        st_value=request.args['st_value'],
        file_offset=request.args['file_offset'],
        func_name=request.args['func_name'],
        size=request.args['size'])


# expects "filename", "st_value", "file_offset", "size", 
@app.route('/get_function_assembly', methods=["GET"])
def get_function_assembly():
    # get sequence of bytes and offset, and pass into disasm
    file_offset = int(request.args['file_offset'])
    if not executable.ex:
        loadExec(request.args['filename'])
    input_bytes = executable.ex.get_bytes(file_offset, int(request.args['size']))
    
    # we want to display the addr in memory where the function is located
    memory_addr = int(request.args['st_value'])
    data = disasm(input_bytes, memory_addr)
    return jsonify(jsonify_capstone(data))

@app.route('/value_at_addr', methods=['GET'])
def value_at_addr():
    return executable.ex.get_bytes(int(request.args['addr'], 16), request.args['len'])

# expects {"filename": "", "substring": "", "start_index": <int>, "num_functions": <int>, "case_sensitive": <bool>}
@app.route('/get_substring_matches', methods=['GET'])
def get_substring_matches():
    substring = request.args['substring']
    if not hasStoredFunctions():
        load_functions(request.args['filename'])
    functions = getFunctionsBySubstring(substring, int(request.args['start_index']), 
        int(request.args['num_functions']), request.args['case_sensitive'] == 'True')
    return jsonify(functions)

@app.route('/get_line_info', methods=["GET"])
def get_line_info():
    begin = int(request.args['begin'])
    size = int(request.args['size'])
    return jsonify(executable.ex.get_function_line_info(begin, size))

@app.route('/get_die_info', methods=["GET"])
def get_DIE_info():
    address = int(request.args['address'])
    return jsonify(executable.ex.get_addr_stack_info(address))

# expects {"src_path": "", "lineno": ""}
@app.route('/source_code_from_path', methods=["POST"])
def source_code_from_path():
    # discard requests that ask for a root path
    if request.form['lineno'] == "":
        return jsonify({})

    path = app.config['SRC_DIR'] + request.form['src_path']
    lineno = int(request.form['lineno'])

    before = ""
    target = ""
    after = ""

    try:
        fp = open(path)
    except:
        return jsonify({})
        
    for fake_index, line in enumerate(fp):
        # because of how enumerate numbers lines
        i = fake_index + 1 
        if i < lineno:
            before += line
        elif i == lineno:
            target += line
        elif i >= lineno:
            after += line
    return jsonify({"before": before, "target": target, "after": after})

# expects {"string_of_bytes": "", arch_type: "", analysis_type: ""}
@app.route('/iaca', methods=['POST'])
def get_iaca():
    hex_data = unhexlify(request.form['string_of_bytes'])
    b = bytearray(hex_data)

    iaca_path = app.config.get('IACA_PATH')
    dyld_lib_path = app.config.get('DYLD_LIBRARY_PATH')
    
    contents, err = iaca.run(b, request.form['arch_type'], request.form['analysis_type'], 
        iaca_path=iaca_path, dyld_lib_path=dyld_lib_path)

    if err:
        return jsonify({'error': {
            'source': err.source,
            'message': err.message,
            }
        })

    if contents:
        return jsonify({'contents': contents})

    return jsonify({'error': 'undefined error'})

@app.route('/get_reg_contents', methods=["GET"])
def get_reg_contents():
    address = int(request.args['address'])
    return jsonify(executable.ex.get_function_reg_contents(address))

# expects {"file_offset": <int>}
@app.route('/get_data_as_cstring', methods=["GET"])
def get_data_as_cstring():
    file_offset = int(request.args['file_offset'])
    return executable.ex.get_data_as_cstring(file_offset)

# debug=True auto reloads whenever server code changes
if __name__ == '__main__':
    app.run(debug=True)



