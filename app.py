from enum import unique
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from wtforms import validators
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap


app = Flask(__name__)
app.secret_key = "123123"

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/dbcompany'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
bootstrap = Bootstrap(app)

class login(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(80), unique= True)
    email = db.Column(db.String(80), unique= True)
    password = db.Column(db.String(100), unique= True)

class suplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kode_barang = db.Column(db.String(80), unique= True)
    namasuplier = db.Column(db.String(80), unique= True)
    harga = db.Column(db.String(100), unique= True)
    satuan = db.Column(db.String(100), unique= True)
    
    def __init__(self, kode_barang, namasuplier, harga, satuan):
        self.kode_barang = kode_barang
        self.namasuplier = namasuplier
        self.harga = harga
        self.satuan = satuan

class karyawan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kode_karyawan = db.Column(db.String(80), unique= True)
    nama_karyawan = db.Column(db.String(80), unique= True)
    email = db.Column(db.String(100), unique= True)
    jabatan = db.Column(db.String(100), unique= True)
    
    def __init__(self, kode_karyawan, nama_karyawan, email, jabatan):
        self.kode_karyawan = kode_karyawan
        self.nama_karyawan = nama_karyawan
        self.email = email
        self.jabatan = jabatan

class stok(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kode_barang = db.Column(db.String(80), unique= True)
    kategori = db.Column(db.String(80), unique= True)
    namabarang = db.Column(db.String(100), unique= True)
    harga = db.Column(db.String(100), unique= True)
    satuan = db.Column(db.String(100), unique= True)
    
    def __init__(self, kode_barang, kategori, namabarang, harga, satuan):
        self.kode_barang = kode_barang
        self.kategori = kategori
        self.namabarang = namabarang
        self.harga = harga
        self.satuan = satuan

class pelanggan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    namapelanggan = db.Column(db.String(80), unique= True)
    alamat = db.Column(db.String(100), unique= True)
    telpon = db.Column(db.String(100), unique= True)
    email = db.Column(db.String(100), unique= True)

    def __init__(self, namapelanggan, alamat, telpon, email):
        self.namapelanggan = namapelanggan
        self.alamat = alamat
        self.telpon = telpon
        self.email = email


        # DATA LOGIN LEVEL

class Login(FlaskForm):
    username = StringField('', validators=[InputRequired()], render_kw={'autofocus':True, "placeholder": "Username"})
    password = PasswordField('', validators=[InputRequired()], render_kw={'autofocus':True, "placeholder": "Password"})
    level = SelectField('', validators=[InputRequired()], choices=[('Admin','Admin'), ('Administrasi','Administrasi')])


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique= True)
    password = db.Column(db.Text)
    level = db.Column(db.String(100), unique= True)

    def __init__(self, username, password, level):
        self.username = username
        if password != '':
            self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
        self.level = level


@app.route('/')
def index():
    return redirect(url_for('login')) 

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'login' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login')) 
    return wrap
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data) and user.level == form.level.data:
                session['login_required'] = True
                session['id'] = user.id
                session['level'] = user.level
                return redirect(url_for('dashboard'))
            message = flash("Username atau password salah")
            return render_template("login.html", message=message, form=form)
    return render_template("login.html", form=form)

@app.route('/dashboard')
def dashboard():
    data1 = db.session.query(User).count()
    data2 = db.session.query(stok).count()

    return render_template('index.html', data1 = data1, data2=data2)

# User Master barang 
@app.route('/masterbarang')
def masterbarang():
    all_data = User.query.all()

    return render_template('masterbarang.html', menu='master' , submenu='barang', data = all_data)


@app.route('/insert', methods = ['POST'])
def insert():
    if request.method == 'POST':
        id = request.form
        kode_barang = request.form['kode_barang']
        nama = request.form['nama']
        harga = request.form['harga']
        satuan = request.form['satuan']

        mydata = User(kode_barang, nama, harga, satuan)
        db.session.add(mydata)
        db.session.commit()
        flash('Succes upload data')

        return redirect(url_for('masterbarang'))

@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        mydata = User.query.get(request.form.get('id'))

        mydata.kode_barang = request.form['kode_barang']
        mydata.nama = request.form['nama']
        mydata.harga = request.form['harga']
        mydata.satuan = request.form['satuan']

        db.session.commit()
        flash("Updated Succes")

        return redirect(url_for('masterbarang'))

@app.route('/delete/<id>/', methods=['GET', 'POST'])
def delete(id):
        mydata = User.query.get(id)
        db.session.delete(mydata)
        db.session.commit()
        flash("Succes delete data")

        return redirect(url_for("masterbarang"))

        # END MASTERBARANG

# ///////////////////////////////////////////////////////////////////////////////////////////

# Master Pelanggan


@app.route('/masterpelanggan')
def masterpelanggan():
    all_data = pelanggan.query.all()

    return render_template('masterpelanggan.html', menu = 'master' , submenu = 'pelanggan', data = all_data)

@app.route('/insertpelanggan', methods = ['POST'])
def insertpelanggan():
    if request.method == 'POST':
        id = request.form
        namapelanggan = request.form['namapelanggan']
        alamat = request.form['alamat']
        telpon = request.form['telpon']
        email = request.form['email']

        mydata = pelanggan(namapelanggan, alamat, telpon, email)
        db.session.add(mydata)
        db.session.commit()
        flash('Succes upload data')

        return redirect(url_for('masterpelanggan'))

# END MASTER PELANGGAN



# ///////////////////////////////////////////////////////////////////////////////////////////

# MASTER SUPPLIER
@app.route('/mastersuplier')
def mastersuplier():
    all_data = suplier.query.all()

    return render_template('mastersuplier.html', menu = 'master' , submenu = 'suplier', data = all_data)

@app.route('/insertsuplier', methods = ['POST'])
def insertsuplier():
    if request.method == 'POST':
        id = request.form
        kode_barang = request.form['kode_barang']
        namasuplier = request.form['namasuplier']
        harga = request.form['harga']
        satuan = request.form['satuan']

        mydata = suplier(kode_barang, namasuplier, harga, satuan)
        db.session.add(mydata)
        db.session.commit()
        flash('Succes upload data')

        return redirect(url_for('mastersuplier'))


@app.route('/updatesuplier', methods=['GET', 'POST'])
def updatesuplier():
    if request.method == 'POST':
        mydata = suplier.query.get(request.form.get('id'))

        mydata.kode_barang = request.form['kode_barang']
        mydata.nama = request.form['namasuplier']
        mydata.harga = request.form['harga']
        mydata.satuan = request.form['satuan']

        db.session.commit()
        flash("Updated Succes")

        return redirect(url_for('mastersuplier'))

@app.route('/deletesuplier/<id>/', methods=['GET', 'POST'])
def deletesuplier(id):
        mydata = suplier.query.get(id)
        db.session.delete(mydata)
        db.session.commit()
        flash("Succes delete data")

        return redirect(url_for("mastersuplier"))

# END MASTER SUPPLIER

# ///////////////////////////////////////////////////////////////////////////////////

# MASTER KARYAWAN
@app.route('/masterkaryawan')
def masterkaryawan():
    all_data = karyawan.query.all()

    return render_template('masterkaryawan.html', menu = 'master' , submenu = 'karyawan', data = all_data)

@app.route('/insertkaryawan', methods = ['POST'])
def insertkaryawan():
    if request.method == 'POST':
        id = request.form
        kode_karyawan = request.form['kode_karyawan']
        nama_karyawan = request.form['nama_karyawan']
        email = request.form['email']
        jabatan = request.form['jabatan']

        mydata = karyawan(kode_karyawan, nama_karyawan, email, jabatan)
        db.session.add(mydata)
        db.session.commit()
        flash('Succes upload data')

        return redirect(url_for('masterkaryawan'))


@app.route('/updatekaryawan', methods=['GET', 'POST'])
def updatekaryawan():
    if request.method == 'POST':
        mydata = karyawan.query.get(request.form.get('id'))

        mydata.kode_karyawan = request.form['kode_karyawan']
        mydata.nama_karyawan = request.form['nama_karyawan']
        mydata.email = request.form['email']
        mydata.jabatan = request.form['jabatan']

        db.session.commit()
        flash("Updated Succes")

        return redirect(url_for('masterkaryawan'))

@app.route('/deletekaryawan/<id>/', methods=['GET', 'POST'])
def deletekaryawan(id):
        mydata = karyawan.query.get(id)
        db.session.delete(mydata)
        db.session.commit()
        flash("Succes delete data")

        return redirect(url_for("masterkaryawan"))

# END MASTER KARYAWAN

# ///////////////////////////////////////////////////////////////////////////////////

# MASTER STOK
@app.route('/masterstok')
def masterstok():
    all_data = stok.query.all()

    return render_template('masterstok.html', menu = 'master' , submenu = 'karyawan', data = all_data)

@app.route('/insertstok', methods = ['POST'])
def insertstok():
    if request.method == 'POST':
        id = request.form
        kode_barang = request.form['kode_barang']
        kategori = request.form['kategori']
        namabarang = request.form['namabarang']
        harga = request.form['harga']
        satuan = request.form['satuan']

        mydata = stok(kode_barang, kategori, namabarang, harga, satuan)
        db.session.add(mydata)
        db.session.commit()
        flash('Succes upload data')

        return redirect(url_for('masterstok'))

@app.route('/updatestok', methods=['GET', 'POST'])
def updatestok():
    if request.method == 'POST':
        mydata = stok.query.get(request.form.get('id'))

        mydata.kode_barang = request.form['kode_barang']
        mydata.kategori = request.form['kategori']
        mydata.namabarang = request.form['namabarang']
        mydata.harga = request.form['harga']
        mydata.satuan = request.form['satuan']

        db.session.commit()
        flash("Updated Succes")

        return redirect(url_for('masterstok'))

@app.route('/deletestok/<id>/', methods=['GET', 'POST'])
def deletestok(id):
        mydata = stok.query.get(id)
        db.session.delete(mydata)
        db.session.commit()
        flash("Succes delete data")

        return redirect(url_for("masterstok"))

# END MASTER KARYAWAN

@app.route('/formpembelian')
def formpembelian():
    return render_template('formpembelian.html', menu='pembelian' , submenu='form')

@app.route('/datapembelian')
def datapembelian():
    return render_template('datapembelian.html', menu='pembelian' , submenu='data1')

@app.route('/formpenjualan')
def formpenjualan():
    return render_template('formpenjualan.html', menu='penjualan' , submenu='form')

@app.route('/datapenjualan')
def datapenjualan():
    return render_template('datapenjualan.html', menu='penjualan' , submenu='data')

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        nama = request.form['nama']
        email = request.form['email']
        password = request.form['password']

        mydata = User(nama, email, password)
        db.session.add(mydata)
        db.session.commit()
        return render_template('login.html')
    return render_template('register.html')


if __name__=="__main__":
    app.run(debug=False)
