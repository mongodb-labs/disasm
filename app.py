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
import argparse

import disassemble as disasm
import iaca
from function_store import storeFunctions, getFunctionsBySubstring, hasStoredFunctions
from executable import ElfExecutable, MachoExecutable, Executable
from disassemble import disasm, jsonify_capstone
from binascii import unhexlify

FILE_LIST = 'file_list.json'
METADATA = '.metadata'

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

## the (global) executable list we're looking at
executables = {}

# home and upload
@app.route('/', methods=['GET', 'POST'])
def index():
    if not os.path.exists(app.config['UPLOAD_DIR']):
        os.makedirs(app.config['UPLOAD_DIR'])
    if not os.path.exists(METADATA):
        os.makedirs(METADATA)
    # Adding a new file.
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        full_path = os.path.abspath(os.path.join(app.config['UPLOAD_DIR'], filename))
        # Save the file in the UPLOAD_DIR directory
        file.save(full_path)
        with open(FILE_LIST, 'a+') as f:
            f.seek(0)
            # Attempt to read the (filename -> filepath) mapping from FILE_LIST
            try:
                file_list_data = json.load(f)
            # If FILE_LIST does not exist, json.load() will raise a ValueError after reading an
            # empty file.
            # If FILE_LIST exists but does not contain a valid JSON file, json.load() will raise 
            # a ValueError.
            # In either case, we need to start with an empty dictionary.
            except ValueError:
                print "Unable to parse JSON from " + FILE_LIST
                file_list_data = {}
            file_list_data[filename] = full_path
            # Store the newly updated list back into the file.
            f.truncate(0)
            json.dump(file_list_data, f)
            return redirect(url_for('functions', filename=filename))
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('files', nargs='*')
        cmdFileList = parser.parse_args().files
        fileMap = {}
        try:
            fileMap = {os.path.basename(open(filename).name) : getFileMetadata(filename) for filename in cmdFileList}
        except:
            for filename in cmdFileList:
                try:
                    with open(filename) as f:
                        fileMap[os.path.basename(f.name)] = getFileMetadata(filename)
                except:
                    fileMap[filename] = ["Error!", "Cannot find file!"]
        existingFileList = getExistingFiles()
        return render_template("index.jinja.html", files=dict(fileMap, **existingFileList))

def getExistingFiles():
    res = {}
    try:
        with open(FILE_LIST, 'r') as f:
            files = json.load(f)
    # If FILE_LIST does not exist, open() will raise a ValueError. 
    # If FILE_LIST does not contain a valid JSON file, json.load() will raise a 
    # ValueErrormeaning.
    # In either case, we need to start with an empty dictionary.
    except (IOError, ValueError):
        files = {}
    # display file info
    for filename, full_path in files.items():
        res[filename] = getFileMetadata(full_path)
    return res

def getFileMetadata(full_path):
    t = os.path.getmtime(full_path)
    timestamp = datetime.datetime.fromtimestamp(t)
    size = os.path.getsize(full_path)
    return [hurry.filesize.size(size), timestamp]

def loadExec(filename):
    # First try to find filename in FILE_LIST
    try:
        with open(FILE_LIST, 'r') as file_list: 
            file_list_data = json.load(file_list)
        path = file_list_data.get(filename)
        if not path:
            raise LookupError
        f = open(path, 'rb')
    # either FILE_LIST does not exist or path does not exist
    except IOError as e:
        print e
    except ValueError:
        print "Unable to load dict from " + FILE_LIST
    except LookupError:
        print "Unable to find " + filename + " in " + FILE_LIST
    # Next try to find it in the uploads folder
    try:
        path = os.path.abspath(os.path.join(app.config['UPLOAD_DIR'] + filename))
        f = open(path, 'rb')
    # If the file still cannot be opened, there's nothing we can do, so we panic
    # This can probably actually be handled a bit cleaner...
    except IOError:
        raise LookupError("Cannot find file '{}'".format(filename))
    a = get_executable(f)
    executables[filename] = a
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
    if not executables.get(filename):
        loadExec(filename)
    functions = executables.get(filename).get_all_functions()
    storeFunctions(filename, functions)

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
    filename = request.args['filename']
    if not executables.get(filename):
        loadExec(filename)
    input_bytes = executables.get(filename).get_bytes(file_offset, int(request.args['size']))
    
    # we want to display the addr in memory where the function is located
    memory_addr = int(request.args['st_value'])
    data = disasm(executables.get(filename), input_bytes, memory_addr)
    return jsonify(jsonify_capstone(data))

# expects {"filename": "", "substring": "", "start_index": <int>, "num_functions": <int>, "case_sensitive": <bool>}
@app.route('/get_substring_matches', methods=['GET'])
def get_substring_matches():
    substring = request.args['substring']
    filename = request.args['filename']
    if not hasStoredFunctions(filename):
        load_functions(filename)
    functions = getFunctionsBySubstring(filename, substring, int(request.args['start_index']), 
        int(request.args['num_functions']), request.args['case_sensitive'] == 'True')
    return jsonify(functions)

# expects "filename", "address"
@app.route('/get_die_info', methods=["GET"])
def get_DIE_info():
    address = int(request.args['address'])
    filename = request.args['filename']
    return jsonify(executables.get(filename).get_addr_stack_info(address))

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

# expects "address", "filename"
@app.route('/get_reg_contents', methods=["GET"])
def get_reg_contents():
    address = int(request.args['address'])
    filename = request.args['filename']
    return jsonify(executables.get(filename).get_function_reg_contents(address))

# expects {"file_offset": <int>, "filename": <str>}
@app.route('/get_data_as_cstring', methods=["GET"])
def get_data_as_cstring():
    file_offset = int(request.args['file_offset'])
    filename = request.args['filename']
    return executables.get(filename).get_data_as_cstring(file_offset)

# debug=True auto reloads whenever server code changes
if __name__ == '__main__':
    app.run(debug=True)



