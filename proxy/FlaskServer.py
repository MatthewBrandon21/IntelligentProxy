from flask import Flask, render_template, jsonify, request
import argparse

app = Flask(__name__)

@app.route('/')
def hello_world():
	return render_template('index.html')

@app.route('/login')
def login_page():
	return render_template('page3.html')

@app.route('/home')
def landing_page():
	return render_template('page2.html')

@app.route('/register')
def register_page():
	return render_template('page1.html')

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
        if(request.get_json()):
            posted_data = request.get_json()
            if(posted_data['data']):
                data = posted_data['data']
                return jsonify(str("Successfully stored  " + str(data)))
            else:
                 data = "Default"
                 return jsonify(str("Successfully stored  " + str(data)))
        else:
            data = "Default"
            return jsonify(str("Successfully stored  " + str(data)))
    else:
         return jsonify(str("Not Post Method"))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flask Sample App')
    parser.add_argument('-p', '--port', help='default port 5000')
    args = parser.parse_args()
    if(args.port):
         port = args.port
    else:
         port = 5000
    app.run(host="0.0.0.0", port=port)
