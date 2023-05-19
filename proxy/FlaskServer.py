from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

@app.route('/')
def hello_world():
	return render_template('index.html')

@app.route("/message", methods=["GET"])
def message():
    posted_data = request.get_json()
    name = posted_data['name']
    return jsonify(" Hope you are having a good time " +  name + "!!!")

@app.route('/api')
def apitest():
    return 'API Success'

@app.route("/name", methods=["POST"])
def setName():
    if request.method=='POST':
        posted_data = request.get_json()
        data = posted_data['data']
        return jsonify(str("Successfully stored  " + str(data)))

if __name__ == '__main__':
	app.run(host="0.0.0.0")
