import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_assets import Environment, Bundle
from werkzeug.utils import secure_filename

from executable import *
from disassemble import disasm, jsonify_capstone

app = Flask(__name__)
app.config['UPLOAD_DIR'] = './uploads/'

assets = Environment(app)

# relative to static dir
scss = Bundle('scss/index.scss', 'scss/disassemble.scss', filters='pyscss', output='css/all.css')
assets.register('css_all', scss)

js = Bundle('js/disassemble.js', 'js/index.js', output='js/all.js')
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

# disassemble into functions
@app.route('/get_functions', methods=['GET'])
def get_functions():
	path = app.config['UPLOAD_DIR'] + request.args['f']
	f = open(path, 'rb')
	
	# determine correct file format of input file
	if Executable.isElf(f):
		ex = ElfExecutable(f)
	elif Executable.isMacho(f):
		ex = MachoExecutable(f)
	else:
		raise Exception("Couldn't find executable format")
	functions = ex.get_all_functions()
	return render_template('disassemble.jinja.html', filename=request.args['f'], functions=functions)

# expects {"filename": "", func_name: "", "offset": "", "size": ""}
@app.route('/disasm_function', methods=['POST'])
def disasm_function():
	file_path = app.config['UPLOAD_DIR'] + request.form['filename']
	f = open(file_path, 'rb')
	ex = ElfExecutable(f)
	input_bytes = ex.get_bytes(int(request.form['offset']), int(request.form['size']))
	data = disasm(input_bytes, int(request.form['offset']))	
	return jsonify(jsonify_capstone(data))


# debug=True auto reloads whenever server code changes
app.run(debug=True)

