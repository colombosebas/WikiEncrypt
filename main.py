import os
from flask import Flask, render_template, request, session
from cryptography.fernet import Fernet

app = Flask(__name__)

def generate_key():
    return Fernet.generate_key()

# Luego puedes utilizar esta función para generar una nueva clave
# y almacenarla de alguna manera segura, por ejemplo, en una variable de entorno.

# Nueva clave generada
nueva_clave = generate_key()
print(nueva_clave)


# Obtener la clave de cifrado desde la variable de entorno
clave_env = os.environ.get('PV_WIKI_PASS')
clave_KeyCrypt = os.environ.get('PV_WIKI_CRYPT')
app.secret_key = os.environ.get('PV_WIKI_SESSION')
limite_intentos = 3

if not clave_env:
    raise ValueError("La clave no está configurada.")

def encrypt_text(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode('utf-8'))

def decrypt_text(text, key):
    cipher = Fernet(key)
    return cipher.decrypt(text.encode('utf-8')).decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado = ''
    error_message = ''
    if 'intentos_incorrectos' not in session:
        session['intentos_incorrectos'] = 0

    if request.method == 'POST':
        texto = request.form['texto']
        clave = request.form['clave']

        if not texto:
            error_message = "Por favor, ingresa un texto."

        if not clave_env:
            error_message = "No se ha configurado la clave correctamente."

        if clave_env != clave:
            session['intentos_incorrectos'] += 1
            error_message = "La clave ingresada no es correcta."

        if session['intentos_incorrectos'] >= limite_intentos:
            session['intentos_incorrectos'] = 0
            resultado = '/static/IncorrectPassword.gif'  # Ruta al gif IncorrectPassword
        else:
            if not error_message:
                if 'encriptar' in request.form:
                    try:
                        resultado = encrypt_text(texto, clave_KeyCrypt)
                        resultado = str(resultado, 'utf-8')
                        error_message = ''
                        session['intentos_incorrectos'] = 0
                    except Exception as e:
                        error_message = f"Error al encriptar: {str(e)}"
                elif 'desencriptar' in request.form:
                    try:
                        resultado = decrypt_text(texto, clave_KeyCrypt)
                        error_message = ''
                        session['intentos_incorrectos'] = 0
                    except Exception as e:
                        error_message = "Error al dsencriptar: {str(e)}"
    else:
        error_message = ''
    return render_template('index.html', resultado=resultado, error_message=error_message)

if __name__ == '__main__':
    app.run(debug=False)
