from flask import Flask

app = Flask(__name__,static_folder='')

@app.route("/<filepath>", methods=['GET'])
def download_file(filepath):
    return app.send_static_file(filepath)  

if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=443, ssl_context=('./server.crt','./server.key'), threaded=True)
    app.run(host='0.0.0.0',  port=80)