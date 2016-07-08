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

import os, datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, g
from flask_assets import Environment, Bundle
from werkzeug.utils import secure_filename
import hurry.filesize

import disassemble as disasm
from function_store import storeFunctions, getFunctions, getFunctionsBySubstring
from executable import *
from disassemble import disasm, jsonify_capstone

app = Flask(__name__)
app.config.from_object('config')

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
	'js/biginteger.js',
	'js/disassembly_analysis.js',
	'js/number_conversion.js',
    'js/jquery.contextMenu.js',
	'js/jquery.ui.position.js',
	'js/highlight.pack.js',
	output='js/disassemble_all.js')
assets.register('js_disassemble', js_disassemble)

## the executable we're looking at
ex = None

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
		return redirect(url_for('disassemble', filename=filename))
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
	global ex
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

@app.route('/disassemble', methods=['GET'])
def disassemble():
	loadExec(request.args['filename'])
	return render_template('disassemble.jinja.html', filename=request.args['filename'])	

# expects {"filename": "", func_name: "", "st_value": "", "file_offset": "", "size": ""}
@app.route('/disasm_function', methods=['POST'])
def disasm_function():
	global ex
	# get sequence of bytes and offset, and pass into disasm
	file_offset = int(request.form['file_offset'])
	input_bytes = ex.get_bytes(file_offset, int(request.form['size']))
	
	# we want to display the addr in memory where the function is located
	memory_addr = int(request.form['st_value'])
	data = disasm(input_bytes, memory_addr)	
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

@app.route('/get_line_info', methods=["GET"])
def get_line_info():
	global ex
	begin = int(request.args['begin'])
	size = int(request.args['size'])
	return jsonify(ex.get_function_line_info(begin, size))

@app.route('/get_die_info', methods=["GET"])
def get_DIE_info():
	global ex
	address = int(request.args['address'])
	return jsonify(ex.get_addr_stack_info(address))

# expects {"src_path": "", "lineno": "", "width": ""}
@app.route('/source_code_from_path', methods=["POST"])
def source_code_from_path():
	global ex
	path = app.config['SRC_DIR'] + request.form['src_path']
	lineno = int(request.form['lineno'])
	width = int(request.form['width'])

	before = ""
	target = ""
	after = ""
	with open(path) as fp:
		for fake_index, line in enumerate(fp):
			# because of how enumerate numbers lines
			i = fake_index - 1 
			if i - width <= lineno <= i + width:
				if i < lineno:
					before += line
				elif i == lineno:
					target += line
				elif i >= lineno:
					after += line
			elif i > lineno + width:
				break
	return jsonify({"before": before, "target": target, "after": after})


# debug=True auto reloads whenever server code changes
app.run(debug=True)

