from flask import request, Flask


app = Flask(__name__)

#wget --post-file=1.txt http://39.98.59.110/api/upload
@app.route('/api/upload', methods=['POST'])
def api_upload():
    request.get_data()
    with open('upload.bin', 'wb') as f:
        f.write(request.data)
    return 'right!'

if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=443, ssl_context=('./server.crt','./server.key'), threaded=True)
    app.run(host='0.0.0.0',  port=80)