from flask import Flask, flash, redirect, render_template, request, send_from_directory, url_for,send_file
from config import config
from flask_mysqldb import MySQL
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from distutils.log import error
from os import remove
from os import path
import paramiko
import os
import sys
import re
import mysql.connector
from models.ModelUser import ModelUser
from models.entities.User import User
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

_direc = [1, 2, 3, 4, 5, 6,7,8,9,10,11,12] #directorios disponibles en el servidor

n = len(_direc)

csrf = CSRFProtect()
app.config['MYSQL_HOST'] ='localhost'
app.config['MYSQL_USER'] ='root'
app.config['MYSQL_PASSWORD'] =''
app.config['MYSQL_DB'] ='flask'
db = MySQL(app)
login_manager_app = LoginManager(app)

def idRol(id): #SACAR EL ID ROL DE CADA USUARIO PARA CON ELLO CARGAR LOS MENUS Y VISTAS
    cursor = db.connection.cursor()
    sql ="SELECT idRol FROM usuarios WHERE id = {}".format(id)
    cursor.execute(sql)
    row = cursor.fetchone()
    idR = int(''.join(map(str, row))) 
    return idR    

@app.route('/add',methods=['GET','POST'])   
def add():
    id = current_user.id
    idR= idRol(id)
    if request.method == 'POST':
        _idR = request.form['idRol']
        username = request.form['username']
        pwd1 = request.form['password']
        pwd2 = request.form['password2']
        fullname = request.form['fullName']
        if(pwd1 == pwd2):
            pwd = generate_password_hash(pwd1)
            cursor = db.connection.cursor()
            cursor.execute("INSERT INTO usuarios (username,password,fullname,idRol) VALUES (%s,%s,%s,%s)",(username,pwd,fullname,_idR)) #tupla para pasar variables en la cadena
            db.connection.commit()
            print("Guardado en DataBase")
            flash('Usuario añadido con éxito')
            return render_template('add.html',idR=idR)
        else:
            flash('Las contraseñas no coinciden')
            return render_template('add.html',idR=idR)
    return render_template('add.html',idR=idR)

@login_manager_app.user_loader
def load_user(id):
    return ModelUser.get_by_id(db, id)


@app.route('/')
def index():
    return redirect(url_for('home'))


@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/lista',methods=['GET','POST'])
def lista():
    id = current_user.id
    idR= idRol(id)
    cursor = db.connection.cursor()
    sql ="SELECT * from usuarios"
    cursor.execute(sql)
    row = cursor.fetchall()
    if request.method == 'POST':
        idB = request.form['id']
        cursor.execute("DELETE FROM usuarios WHERE id=%s",(idB))
        db.connection.commit()
        flash('Usuario eliminado correctamente')
        print("Data Base Actualizada")
        return redirect(url_for('lista'))
    return render_template('lista.html',users=row,idR=idR)


@app.route('/admin')
def admin():
    id = current_user.id
    idR= idRol(id)
    if(idR== 2):
        return render_template('admin.html',idR=idR)
    else:
        flash("No tienes permiso para ver esta página")    
        return render_template('logeado.html',idR=idR)


@app.route('/logeado')
def logeado():
    id = current_user.id
    idR= idRol(id)
    return render_template('logeado.html',idR=idR)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
       # print(request.form['username'])
       # print(request.form['password'])
        user = User(0, request.form['username'], request.form['password'])
        logged_user = ModelUser.login(db, user)
        if logged_user != None:
            if logged_user.password:
                login_user(logged_user)
                return redirect(url_for('logeado'))
            else:
                flash("Invalid password")
                return render_template('auth/login.html')
        else:
            flash("User not found")

        return render_template('auth/login.html')
    else:
        return render_template('auth/login.html')


@app.route('/logout')
def logout():
    logout_user
    return redirect(url_for('home'))

@app.route('/descarga', methods=['GET', 'POST'])
def descarga():
    id = request.form['server']
    conexionFree = False
    comando = 'SOURCE_33_RUN_SHORT'+id
    ruta= '/home/pilarg/archivo.zip'
    destino = r'C:/Users/pilig/tesis/flask/archivos'
    idU = current_user.id
    idR= idRol(idU)
    if request.method == 'POST':
        try:
            transport = paramiko.Transport((r'148.224.242.90', 22))
            transport.banner_timeout = 200
            transport.default_window_size=paramiko.common.MAX_WINDOW_SIZE
            transport.packetizer.REKEY_BYTES = pow(2, 40)  # 1TB max, this is a security degradation!
            transport.packetizer.REKEY_PACKETS = pow(2, 40)  # 1TB max, this is a security degradation!
            transport.connect(username=r'pilarg', password=r'PilardelRocio2022')
            print("Conexion al servidor exitosa")
            conexionFree = True
        except:
            conexionFree = False
            print("Conexion al servidor fallida")
        
        if(conexionFree):
            # SFTP PROTOCOLO SEGURO DE TRANSFERENCIA DE ARCHIVOS
            sftp = paramiko.SFTPClient.from_transport(transport)
            ssh = paramiko.SSHClient()  # sesión del servidor
            ssh._transport = transport
            try:
                vmtransport = ssh.get_transport()
                vmtransport.default_max_packet_size = 100000000
                vmtransport.default_window_size = 100000000
                boltzam_ip = (r'148.224.242.158', 22)
                nvidia_ip = (r'148.224.242.90', 22)
                vmchannel = vmtransport.open_channel(r"direct-tcpip", boltzam_ip, nvidia_ip)
                boltzman = paramiko.SSHClient()
                boltzman.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                boltzman.connect(r'148.224.242.158', username=r'pilarg', password=r'pilarg2022', sock=vmchannel)        
                try:
                    ftp_client = boltzman.open_sftp()
                    stdin, stdout, stderr = boltzman.exec_command('zip -r archivo.zip '+comando)
                    print('Archivo ZIP creado con éxito')
                    if(ftp_client.get(r"/home/pilarg/archivo.zip",r"C:/Users/pilig/tesis/flask/archivos/archivo.zip")):
                        print('descarga exitosa')
                    else:
                        print('descargar de zip fallida por server')
                    stdin, stdout, stderr = boltzman.exec_command('rm archivo.zip')
                    flash('Archivo descargado con éxito!')
                    return send_from_directory(destino,'archivo.zip',as_attachment = True)
                except:
                    print("Archivo Zip fallido")
                ftp_client.close()
            except Exception as e:
                print(e)
        sftp.close()
        boltzman.close()
        transport.close()
    return render_template('decidir.html',id=id,idR=idR)

@app.route('/perfil',methods=['GET','POST'])
def perfil():
    id = current_user.id
    cursor = db.connection.cursor()
    sql ="SELECT id, username, fullname,password,idRol FROM usuarios WHERE id = {}".format(id)
    cursor.execute(sql)
    row = cursor.fetchone()
    idR= idRol(id)
    if request.method == 'GET':
        return render_template('perfil.html',user=row)
    if request.method == 'POST':
        id = request.form['id']
        pwd1 = request.form['pwd1']
        pwd2 = request.form['pwd2']
        if pwd1 != pwd2:
            flash("Las contraseñas no coinciden, vuelva a intentarlo")
            return render_template('perfil.html',user=row,idR=idR)
        else:
            pwd = generate_password_hash(pwd1)
            cursor = db.connection.cursor()
            cursor.execute("UPDATE usuarios SET password= %s WHERE id= %s",(pwd,id)) #tupla para pasar variables en la cadena
            db.connection.commit()
            print("DataBase actualizada")
            flash("Contraseña actualizada con éxito!")
            return render_template('perfil.html',user=row,idR=idR)
    return render_template('perfil.html',user=row,idR=idR)

@app.route('/liberar', methods=['GET','POST'])
def liberar():
    if request.method == 'POST':
        id = request.form['server']
        conexionFree = False
        comando = 'cd SOURCE_33_RUN_SHORT'+id
        idU = current_user.id
        idR= idRol(idU)
        try:
            transport = paramiko.Transport((r'148.224.242.90', 22))
            transport.banner_timeout = 200
            transport.connect(username=r'pilarg', password=r'PilardelRocio2022')
            print("Conexion al servidor exitosa")
            conexionFree = True
        except Exception as e:
            print(e)
            conexionFree = False
            print("Conexion al servidor fallida")

        if(conexionFree):
            ssh = paramiko.SSHClient()  # sesión del servidor
            ssh._transport = transport

            try:
                vmtransport = ssh.get_transport()
                boltzam_ip = (r'148.224.242.158', 22)
                nvidia_ip = (r'148.224.242.90', 22)
                vmchannel = vmtransport.open_channel(
                    r"direct-tcpip", boltzam_ip, nvidia_ip)

                boltzman = paramiko.SSHClient()
                boltzman.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                boltzman.connect(r'148.224.242.158', username=r'pilarg',
                                 password=r'pilarg2022', sock=vmchannel)

                stdin, stdout, stderr = boltzman.exec_command(comando +';rm *.dat')
                stdin, stdout, stderr = boltzman.exec_command(comando + ';rm conf_ini_*')
                stdin, stdout, stderr = boltzman.exec_command(comando + ';rm input.particles')
                stdin, stdout, stderr = boltzman.exec_command(comando + ';rm input.potential')
                stdin, stdout, stderr = boltzman.exec_command(comando + ';rm input.simulation')
                _direc.append(int(id))
                print(_direc)
                cursor = db.connection.cursor()
                cursor.execute("DELETE FROM directorios WHERE Directorio=%s",(id)) #tupla para pasar variables en la cadena
                db.connection.commit()
                print("Data Base Actualizada")
                if path.exists(r'C:/Users/pilig/tesis/flask/archivos/archivo.zip'):
                    remove(r'C:/Users/pilig/tesis/flask/archivos/archivo.zip')
                return render_template('eliminar.html',idR=idR)
            except Exception as e:
                print(e)
            boltzman.close()
            transport.close()
        return render_template('eliminar.html', id=id,idR=idR)
    else:
        return render_template('liberar.html',idR=idR)


@app.route('/eliminar',methods=['GET','POST'])
def eliminar():
    if request.method == 'POST':
        id = request.form['server']
        cursor = db.connection.cursor()
        sql ="SELECT pid FROM directorios WHERE Directorio = {}".format(id)
        cursor.execute(sql)
        consulta = cursor.fetchall()
        row = ''.join(''.join(map(str, tup)) for tup in consulta)
        comando= 'kill -9 ' +row
        comando2 = 'cd SOURCE_33_RUN_SHORT'+id
        conexionFree = False
        idU = current_user.id
        idR= idRol(idU)
        try:
            transport = paramiko.Transport((r'148.224.242.90', 22))
            transport.banner_timeout = 200
            transport.connect(username=r'pilarg', password=r'PilardelRocio2022')
            print("Conexion al servidor exitosa")
            conexionFree = True
        except Exception as e:
            print(e)
            conexionFree = False
            print("Conexion al servidor fallida")

        if(conexionFree):
            ssh = paramiko.SSHClient()  # sesión del servidor
            ssh._transport = transport

            try:
                vmtransport = ssh.get_transport()
                boltzam_ip = (r'148.224.242.158', 22)
                nvidia_ip = (r'148.224.242.90', 22)
                vmchannel = vmtransport.open_channel(
                    r"direct-tcpip", boltzam_ip, nvidia_ip)

                boltzman = paramiko.SSHClient()
                boltzman.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                boltzman.connect(r'148.224.242.158', username=r'pilarg',
                                 password=r'pilarg2022', sock=vmchannel)

                stdin, stdout, stderr = boltzman.exec_command(comando)
                stdin, stdout, stderr = boltzman.exec_command(comando2 +';rm *.dat')
                stdin, stdout, stderr = boltzman.exec_command(comando2 + ';rm conf_ini_*')
                stdin, stdout, stderr = boltzman.exec_command(comando2 + ';rm input.particles')
                stdin, stdout, stderr = boltzman.exec_command(comando2 + ';rm input.potential')
                stdin, stdout, stderr = boltzman.exec_command(comando2 + ';rm input.simulation')
                _direc.append(int(id))
                print(_direc)
                cursor.execute("DELETE FROM directorios WHERE Directorio=%s",(id)) #tupla para pasar variables en la cadena
                db.connection.commit()
                print("Data Base Actualizada")
                if path.exists(r'C:/Users/pilig/tesis/flask/archivos/archivo.zip'):
                    remove(r'C:/Users/pilig/tesis/flask/archivos/archivo.zip')
                return render_template('eliminar.html',idR=idR)
            except Exception as e:
                print(e)
            boltzman.close()
            transport.close()
        return render_template('eliminar.html', id=id,idR=idR)
    else:
       return render_template('eliminar.html',idR=idR)


@app.route('/accion', methods=['GET', 'POST'])
def accion():
    idU = current_user.id
    idR= idRol(idU)
    if request.method == 'POST':
        id = request.form.get('comp_select')
        return render_template('decidir.html', id=id,idR=idR)
    else:
       return render_template('documentos.html',idR=idR)

@app.route('/documentos',methods=['GET', 'POST'])
def documentos():
    row = ''
    conexionFree = False
    cd = []
    pid_ =[]
    id = current_user.id
    idR= idRol(id)
    try:
            cursor = db.connection.cursor()
            sql ="SELECT Directorio FROM directorios WHERE id = {}".format(id)
            cursor.execute(sql)
            consulta = cursor.fetchall()
            row = ''.join(''.join(map(str, tup)) for tup in consulta)
            print(row)
    except Exception as e:
            raise Exception(e)
    if row != None:
        try:
            transport = paramiko.Transport((r'148.224.242.90', 22))
            transport.banner_timeout = 200
            transport.connect(username=r'pilarg', password=r'PilardelRocio2022')
            print("Conexion al servidor exitosa")
            conexionFree = True
        except Exception as e:
            print(e)
            conexionFree = False
            print("Conexion al servidor fallida")
        if(conexionFree):
 
            sftp = paramiko.SFTPClient.from_transport(transport)
            ssh = paramiko.SSHClient()  # sesión del servidor
            ssh._transport = transport

            try:
                vmtransport = ssh.get_transport()
                boltzam_ip = (r'148.224.242.158', 22)
                nvidia_ip = (r'148.224.242.90', 22)
                vmchannel = vmtransport.open_channel(
                    r"direct-tcpip", boltzam_ip, nvidia_ip)

                boltzman = paramiko.SSHClient()
                boltzman.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                boltzman.connect(r'148.224.242.158', username=r'pilarg',
                                 password=r'pilarg2022', sock=vmchannel)
                for i in row:
                    comando = 'cd SOURCE_33_RUN_SHORT' + i+';ls'
                    stdin, stdout, stderr = boltzman.exec_command(comando)
                    cd.append(stdout.read().decode())
            except Exception as e:
                print(e)
            sftp.close()
        else:
            print("No se pudo establecer canal de transferencia de archivos")
        boltzman.close()
        transport.close()
        return render_template('documentos.html',direc = row,cd=cd,idR=idR)
    else:
        return render_template('documentos.html',idR=idR)


@app.route('/directorios', methods=['GET', 'POST'])
def directorios():
    conexionFree = False
    cd1 = '/'
    cd2 = '/'
    cd3 = '/'
    cd4 = '/'
    cd5 = '/'
    cd6 = '/'
    cd7 = '/'
    cd8 = '/'
    cd9 = '/'
    cd10 = '/'
    cd11 = '/'
    cd12 = '/'
    id = current_user.id
    idR= idRol(id)
    try:
        transport = paramiko.Transport((r'148.224.242.90', 22))
        transport.banner_timeout = 200
        transport.connect(username=r'pilarg', password=r'PilardelRocio2022')
        print("Conexion al servidor exitosa")
        conexionFree = True
    except Exception as e:
        print(e)
        conexionFree = False
        print("Conexion al servidor fallida")

    if(conexionFree):
            # SFTP PROTOCOLO SEGURO DE TRANSFERENCIA DE ARCHIVOS
            sftp = paramiko.SFTPClient.from_transport(transport)

            ssh = paramiko.SSHClient()  # sesión del servidor
            ssh._transport = transport

            try:
                vmtransport = ssh.get_transport()
                boltzam_ip = (r'148.224.242.158', 22)
                nvidia_ip = (r'148.224.242.90', 22)
                vmchannel = vmtransport.open_channel(
                    r"direct-tcpip", boltzam_ip, nvidia_ip)

                boltzman = paramiko.SSHClient()
                boltzman.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                boltzman.connect(r'148.224.242.158', username=r'pilarg',
                                 password=r'pilarg2022', sock=vmchannel)

                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT1;ls')
                cd1 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT2;ls')
                cd2 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT3;ls')
                cd3 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT4;ls')
                cd4 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT5;ls')
                cd5 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT6;ls')
                cd6 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT7;ls')
                cd7 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT8;ls')
                cd8 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT9;ls')
                cd9 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT10;ls')
                cd10 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT11;ls')
                cd11 = stdout.read().decode()
                stdin, stdout, stderr = boltzman.exec_command(
                    'cd SOURCE_33_RUN_SHORT12;ls')
                cd12 = stdout.read().decode()
                cd = [cd1,cd1, cd2, cd3, cd4, cd5, cd6,cd7,cd8,cd9,cd10,cd11,cd12]
                return render_template('escoger.html', cd=cd, direc=_direc, n=n,idR=idR)
            except Exception as e:
                print(e)
            sftp.close()
            boltzman.close()
            transport.close()
    else:
        print("No se pudo establecer canal de transferencia de archivos")
    return render_template('logeado.html',idR=idR)


@app.route('/escoger/', methods=['GET', 'POST'])
def escoger():
    idA = current_user.id
    idR= idRol(idA)
    if request.method == 'POST':
        id = request.form.get('comp_select')
        idU = request.form.get('idU')
        return render_template('archivos.html', id=id,idU=idU,idR=idA)
    else:
       return render_template('escoger.html',idR=idR)


@app.route("/archivos", methods=["GET", "POST"])
def archivos():
    conexionFree = False
    idA = current_user.id
    idR= idRol(idA)
    if request.method == 'POST':
        id = request.form['server']
        idU = request.form['idU']
        f1 = request.files['file1']
        f2 = request.files['file2']
        f3 = request.files['file3']
        f4 = request.files['file4']

        fn1 = f1.filename
        fn2 = f2.filename
        fn3 = f3.filename
        fn4 = f4.filename

        ruta = "/home/pilarg/SOURCE_33_RUN_SHORT"+id + "/"
        try:
            # Hostname, Port
            transport = paramiko.Transport((r'148.224.242.90', 22))
            # time to connect
            transport.banner_timeout = 200
             # Username y Password
            transport.connect(username=r'pilarg',
                              password=r'PilardelRocio2022')
            print("Conexion al servidor exitosa")
            conexionFree = True
        except Exception as e:
            print(e)
            conexionFree = False
            print("Conexion al servidor fallida")

        if(conexionFree):
            # SFTP PROTOCOLO SEGURO DE TRANSFERENCIA DE ARCHIVOS
            sftp = paramiko.SFTPClient.from_transport(transport)

            ssh = paramiko.SSHClient()  # sesión del servidor
            ssh._transport = transport

            try:
                vmtransport = ssh.get_transport()
                boltzam_ip = (r'148.224.242.158', 22)
                nvidia_ip = (r'148.224.242.90', 22)
                vmchannel = vmtransport.open_channel(
                    r"direct-tcpip", boltzam_ip, nvidia_ip)

                boltzman = paramiko.SSHClient()
                boltzman.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                boltzman.connect(r'148.224.242.158', username=r'pilarg',
                                 password=r'pilarg2022', sock=vmchannel)

                try:
                    ftp_client = boltzman.open_sftp()
                    if(ftp_client.putfo(f1, ruta+fn1) and ftp_client.putfo(f2, ruta+fn2)
                        and ftp_client.putfo(f3, ruta+fn3) and ftp_client.putfo(f4, ruta+fn4)):
                        flash("Archivos subidos")
                        return render_template('archivos.html', continuar=True, id=id, idU=idU,idR=idR)
                    else:
                        flash("Los archivos no pudieron ser enviados")
                        print("error en la subida de archivos")
                    ftp_client.close()
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
            sftp.close()
        else:
            print("No se pudo establecer canal de transferencia de archivos")
            # flash("Conexión al servidor exitosa!")
        boltzman.close()
        transport.close()
        return render_template('archivos.html',idR=idR)
    else:
        return render_template('archivos.html', id=id,idR=idR)


@app.route("/calculos", methods=["GET", "POST"])
def calculos():
    conexionFree = False
    idA = current_user.id
    idR= idRol(idA)
    if request.method == 'POST':
        id = request.form['server']
        idU = request.form['idU']
        comando = 'cd SOURCE_33_RUN_SHORT'+id
        try:
            transport = paramiko.Transport((r'148.224.242.90', 22))
            transport.banner_timeout = 200
            transport.connect(username=r'pilarg',
                              password=r'PilardelRocio2022')
            conexionFree = True
        except:
            conexionFree = False
            flash("Conexión al servidor fallida")

        if(conexionFree):
            ssh = paramiko.SSHClient()
            ssh._transport = transport
            try:
                vmtransport = ssh.get_transport()
                boltzam_ip = (r'148.224.242.158', 22)
                nvidia_ip = (r'148.224.242.90', 22)
                vmchannel = vmtransport.open_channel(
                    r"direct-tcpip", boltzam_ip, nvidia_ip)

                boltzman = paramiko.SSHClient()
                boltzman.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                boltzman.connect(r'148.224.242.158', username=r'pilarg',
                                 password=r'pilarg2022', sock=vmchannel)
                try:
                    stdin, stdout, stderr = boltzman.exec_command(
                        comando+';nohup /home/compiladores/MBD_EXEC/mbd_gen >/dev/null 2>&1 &')
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        print("comando ejecutado")
                        stdin, stdout, stderr = boltzman.exec_command('echo $$; exec ;'+comando+';nohup /home/compiladores/MBD_EXEC/mbd_f90_serial >salida.txt &')
                        pid = int(stdout.readline())
                        pid=pid+1
                        print(pid)
                        try:
                                cursor = db.connection.cursor()
                                cursor.execute("INSERT INTO directorios (id, Directorio,pid) VALUES (%s,%s,%s)",(idU,id,pid)) #tupla para pasar variables en la cadena
                                db.connection.commit()
                                print("Guardado en DataBase")
                                
                                if (int(id) in _direc):
                                    _direc.remove(int(id))
                                    return render_template('done.html',idR=idR)
                                else:
                                    print('no paso nah')
                        except Exception as e:
                            raise Exception(e)
                        exit_status = stdout.channel.recv_exit_status()
                        if exit_status == 0:
                            print("Calculos realizados con éxito")
                        else:
                            flash("mbd_f90 fallido")
                            print('Error en cálculos')
                    else:
                        flash("Error al ejecutar mdbgen")
                        print("Error", exit_status)        
                except Exception as e:
                    flash("Error al ejecutar mdbgen")
                    print(e)
            except:
                print("Conexion con Boltzman fallida")   
                flash("Error al conectarse con el servidor")
            boltzman.close()
            transport.close()
        else:
            print("No se pudo establecer canal de transferencia de archivos")
        return render_template('calculos.html',id=id,idR=idR)
    else:
        if request.args.get('server', None):
            id = request.args['server']
        return render_template('calculos.html',id=id,idR=idR)

def status_401(error):
    flash("Inicia sesión para acceder a esta página!")
    return redirect(url_for('login'))


def status_404(error):
    return "<h1>Página no encontrada</h1>"


if __name__ == '__main__':
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    app.run()
