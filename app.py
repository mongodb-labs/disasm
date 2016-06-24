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

import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_assets import Environment, Bundle
from werkzeug.utils import secure_filename
import threading

import disassemble as disasm
import utils
from function_store import storeFunctions, getFunctions, getFunctionsBySubstring
from executable import *
from disassemble import disasm, jsonify_capstone

app = Flask(__name__)
app.config['UPLOAD_DIR'] = './uploads/'

assets = Environment(app)

# relative to static dir

scss = Bundle('scss/index.scss', 
	'scss/disassemble.scss', 
	filters='pyscss', 
	output='css/all.css')
assets.register('css_all', scss)

js_index = Bundle('js/index.js', 
	output='js/index_all.js')
assets.register('js_index', js_index)

js_disassemble = Bundle('js/rivets.js', 
	'js/disassemble.js', 
	'js/autocomplete.js',
    'js/jquery.contextMenu.js',
	'js/jquery.ui.position.js',
	output='js/disassemble_all.js')
assets.register('js_disassemble', js_disassemble)

# home and upload
@app.route('/', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		file = request.files['file']
		filename = secure_filename(file.filename)
		if not os.path.exists(app.config['UPLOAD_DIR']):
			os.makedirs(app.config['UPLOAD_DIR'])
		file.save(os.path.join(app.config['UPLOAD_DIR'], filename))
		# thread = threading.Thread(target=loadExec, args=(filename,))
		# thread.start()
		loadExec(filename)
		return redirect(url_for('get_functions', f=filename, start_index=0, num_functions=100))
	else:
		return render_template("index.jinja.html")

def loadExec(filename):
	path = app.config['UPLOAD_DIR'] + filename
	f = open(path, 'rb')
	ex = get_executable(f)
	functions = ex.get_all_functions()
	storeFunctions(functions)
	print "Done loading the executable"

## determine which kind of executable
def get_executable(f):
	if Executable.isElf(f):
		return ElfExecutable(f)
	elif Executable.isMacho(f):
		return MachoExecutable(f)
	else:
		raise Exception("Couldn't find executable format")

# disassemble into functions
# expects {"f": "", "start_index": <int>, "num_functions": <int>}
@app.route('/get_functions', methods=['GET'])
def get_functions():
	functions = getFunctions(int(request.args['start_index']), int(request.args['num_functions']))
	return render_template('disassemble.jinja.html', filename=request.args['f'], functions=functions)

# expects {"filename": "", func_name: "", "offset": "", "size": ""}
@app.route('/disasm_function', methods=['POST'])
def disasm_function():
	file_path = app.config['UPLOAD_DIR'] + request.form['filename']
	f = open(file_path, 'rb')
	ex = get_executable(f)

	# get sequence of bytes and offset, and pass into disasm
	offset = int(request.form['offset'])
	input_bytes = ex.get_bytes(offset, int(request.form['size']))
	data = disasm(input_bytes, offset)	
	return jsonify(jsonify_capstone(data))

# expects {"substring": "", "start_index": <int>, "num_functions": <int>, "case_sensitive": <bool>}
@app.route('/get_substring_matches', methods=['GET'])
def get_substring_matches():
	print "Starting to process substring"
	substring = request.args['substring']
	functions = getFunctionsBySubstring(substring, int(request.args['start_index']), 
		int(request.args['num_functions']), request.args['case_sensitive'] == 'True')
	print "Finished processing substring"
	return jsonify(functions)

# debug=True auto reloads whenever server code changes
app.run(debug=True)

