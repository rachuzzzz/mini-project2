from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/citizen-login')
def citizen_login():
    return render_template('clogin3.html')

@app.route('/admin-login')
def admin_login():
    return render_template('alogin.html')

@app.route('/contractor-login')
def contractor_login():
    return render_template('blogin.html')

@app.route('/signup')
def signup():
    return render_template('clogin2.html')

if __name__ == '__main__':
    app.run(debug=True)  

