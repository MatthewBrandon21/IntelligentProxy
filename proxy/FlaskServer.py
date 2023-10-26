from flask import Flask, render_template, jsonify, request
# pip install Flask-Caching
from flask_caching import Cache
import argparse

config = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300
}
app = Flask(__name__)
app.config.from_mapping(config)
cache = Cache(app)

@app.route('/')
@cache.cached(timeout=None)
def hello_world():
	return render_template('index.html')

@app.route('/login')
@cache.cached(timeout=None)
def login_page():
	return render_template('page3.html')

@app.route('/home')
@cache.cached(timeout=None)
def landing_page():
	return render_template('page2.html')

@app.route('/register')
@cache.cached(timeout=None)
def register_page():
	return render_template('page1.html')

@app.route('/documentation')
@cache.cached(timeout=None)
def documentation_page():
	return render_template('page5.html')

@app.route('/singlepageapplication')
@cache.cached(timeout=None)
def single_page():
	return render_template('page4.html')

@app.route("/message", methods=["GET"])
@cache.cached(timeout=300)
def message():
    posted_data = request.get_json()
    name = posted_data['name']
    return jsonify(" Hope you are having a good time " +  name + "!!!")

@app.route('/api')
@cache.cached(timeout=None)
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

@app.errorhandler(404)
@cache.cached(timeout=None)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flask Sample App')
    parser.add_argument('-p', '--port', help='default port 5000')
    args = parser.parse_args()
    if(args.port):
         port = args.port
    else:
         port = 5000
    app.run(host="0.0.0.0", port=port)
