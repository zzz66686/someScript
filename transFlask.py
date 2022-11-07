from flask import request, Flask


app = Flask(__name__,static_folder='')



@app.route("/<filepath>", methods=['GET'])
def download_file(filepath):
    return app.send_static_file(filepath)  



#wget --post-file=us.tar.gz http://192.168.137.187/api/us
@app.route('/api/<filepath>', methods=['POST'])
def api_upload(filepath):
    request.get_data()
    with open(filepath + '.bin', 'wb') as f:
        f.write(request.data)
    return 'right!'

if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=443, ssl_context=('./server.crt','./server.key'), threaded=True)
    app.run(host='0.0.0.0',  port=80)