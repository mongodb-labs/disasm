import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_assets import Environment, Bundle
from werkzeug.utils import secure_filename
import threading

import disassemble as disasm
import utils
from function_store import (storeFunctionNames, getFunctionsBySubstring)
from executable import *
from disassemble import disasm, jsonify_capstone

app = Flask(__name__)
app.config['UPLOAD_DIR'] = './uploads/'

assets = Environment(app)

# relative to static dir
scss = Bundle('scss/index.scss', 'scss/disassemble.scss', filters='pyscss', output='css/all.css')
assets.register('css_all', scss)

js = Bundle('js/disassemble.js', 'js/index.js', 'js/autocomplete.js', output='js/all.js')
assets.register('js_all', js)

# home and upload
@app.route('/', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		file = request.files['file']
		filename = secure_filename(file.filename)
		if not os.path.exists(app.config['UPLOAD_DIR']):
			os.makedirs(app.config['UPLOAD_DIR'])
		file.save(os.path.join(app.config['UPLOAD_DIR'], filename))
		return redirect(url_for('get_functions', f=filename))
	else:
		return render_template("index.jinja.html")

## determine which kind of executable
def get_executable(f):
	if Executable.isElf(f):
		return ElfExecutable(f)
	elif Executable.isMacho(f):
		return MachoExecutable(f)
	else:
		raise Exception("Couldn't find executable format")

# disassemble into functions
@app.route('/get_functions', methods=['GET'])
def get_functions():
	path = app.config['UPLOAD_DIR'] + request.args['f']
	f = open(path, 'rb')
	ex = get_executable(f)
	functions = ex.get_all_functions()
        # Store the relevant function information to be obtained later
	thread = threading.Thread(target=storeFunctionNames, args=(functions,))
	thread.start()
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

@app.route('/get_substring_matches', methods=['GET'])
def get_substring_matches():
	substring = request.args['substring']
	functions = getFunctionsBySubstring(substring)
	return jsonify(functions)

# debug=True auto reloads whenever server code changes
app.run(debug=True)

