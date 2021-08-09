#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  
'''
FARHAT Oussama
'''
#import matplotlib.pyplot as plt
from flask import Flask, render_template, redirect, url_for , send_from_directory
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime,timedelta
import datetime as datee
import io
import sqlite3
from flask import Flask, render_template, send_file, make_response, request , redirect ,Response
from flask_socketio import SocketIO, emit
from threading import Thread, Event
from threading import Lock
import threading
import time
import json
import sqlite3
import threading
from flask_cors import CORS
from flask import Flask, request, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import random 
import datetime
import numpy as np
from flask_wtf import Form
from wtforms.fields import DateField
import pandas as pd

from datetime import datetime
from pytz import timezone
import serial
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
import os

#start the loop

#socket and flask app########################################################################################################################################
app = Flask(__name__, static_url_path='/static')
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Login.db'
bootstrap = Bootstrap(app)


UPLOAD_DIRECTORY = "static/project"

if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#########################################################################################################################Mail Flask
s = URLSafeTimedSerializer('Thisisasecret!')



#socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)
thread = Thread()
thread_stop_event = Event()
import signal
def keyboardInterruptHandler(signal, frame):
    print("KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
    exit(0)

signal.signal(signal.SIGINT, keyboardInterruptHandler)

################################################################### User management 
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route('/',methods=['GET', 'POST'])
def index():

    return render_template('index.html')


############################################################### login route 
@app.route('/login', methods=['GET', 'POST'])
def login():
    global ID
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            ##return ID
            con=sqlite3.connect('Login.db')
            cursor=con.cursor()  
            sql_select_query = """SELECT * FROM user where username=?"""    
            cursor.execute(sql_select_query, (user.username,))
            data = cursor.fetchall()
            con.close()
            #ADD CHARTNUMBER ALLOWED
            if check_password_hash(user.password, form.password.data) and user.confirmed==True:
                login_user(user)
                return redirect(url_for('adminPanel'))
            else : 
                message = "Not confirmed yet"
                return render_template('Error.html', message=message)               
               
        # return '<h1>Invalid username or password</h1>'
        message = "Invalid username or password"
        return render_template('Error.html', message=message)        
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = ""
    form = RegisterForm()

    if form.validate_on_submit():
        #if checkUserUsername(form.username.data) == 1 and checkUserEmail(form.email.data) == 1 : 
        user1 = User.query.filter_by(username=form.username.data).first() 
        user2 = User.query.filter_by(username=form.email.data).first()
        if user1 == None and user2 == None : 

                hashed_password = generate_password_hash(form.password.data, method='sha256')
                new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, confirmed=True)
                ##################################################################################################################Flask mail
                db.session.add(new_user)
                db.session.commit()
                return render_template('login.html', form=form)

        else : 
            message = "Username or Email is already used"
            return render_template('signup.html', message=message,form=form)               

    return render_template('signup.html', form=form,message=message)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
#User confirmation 

 

def readTypeZone(username) : 
    con=sqlite3.connect('Domains.db')
    cursor=con.cursor()  
    sqlite_select_query = """SELECT timeZone from TimeZone WHERE (username=?) """
    cursor.execute(sqlite_select_query,(username,))
    records = cursor.fetchall()
    if not records: 
        sqlite_select_query = """INSERT into TimeZone (username) values (?) """
        cursor.execute(sqlite_select_query,(username,))
        con.commit()        
        con.close()
        return "server"        
    else  : 
        con.close()        
        return records[0][0]



@app.route("/local", methods=['GET'])
def localTime():
    print("browser time: ", )
    con=sqlite3.connect('Domains.db')
    cursor=con.cursor()  
    sqlite_select_query = """UPDATE TimeZone SET timeZone=? WHERE username=? """
    cursor.execute(sqlite_select_query, (request.args.get("time"),current_user.username))
    con.commit()
    con.close()    
    return "Done" 



@app.route("/v1/events", methods=['POST'])
def events():
    
    print(request.json)

    return "Done" 

@app.route('/Admin' , methods=['GET','POST'])
@login_required
def adminPanel():
    if current_user.username == "oussama" : 
        
        conn = sqlite3.connect('firmware.db')
        cursor = conn.cursor()
        sql_update_query = """SELECT * from DecisionUpdate"""
        cursor.execute(sql_update_query)    
        records = cursor.fetchall()

        templateData = {
          'Nodes':records,
          'name': current_user.username 
        }
        return render_template('new_Admin.html', **templateData)
    else : 
        return render_template('index.html')

@app.route('/uploader', methods = ['GET', 'POST'])
@login_required
def upload_file():
    print("enter")
    if request.method == 'POST':
        firmwareFile = request.files['firmware']
        fileSystemFile = request.files['fileSystem']
        deployAs = request.form['deployAs']

        print(deployAs)
        print(request.form)
        firmwareFile.save(UPLOAD_DIRECTORY   +  "/" + deployAs + "_firmware_"   + secure_filename(firmwareFile.filename))
        fileSystemFile.save(UPLOAD_DIRECTORY +  "/" + deployAs + "_fileSystem_" + secure_filename(fileSystemFile.filename))

        if current_user.username == "oussama" : 
                #insert into database 

            """Download a file."""
            conn = sqlite3.connect('firmware.db')
            cursor = conn.cursor()
            sqlite_select_query = """UPDATE DecisionUpdate SET updateFS=?,updateF=? WHERE deployAs=?"""
            cursor.execute(sqlite_select_query,("1","1",deployAs,))
            conn.commit()

            sql_update_query = """SELECT * from DecisionUpdate"""
            cursor.execute(sql_update_query)    
            records = cursor.fetchall()

            templateData = {
              'Nodes':records,
              'name': current_user.username 
            }
            return render_template('new_Admin.html', **templateData)
        else : 
    
            return render_template('index.html')
@app.route("/id/<mac>/project/<deploy>")
def saveNewDevice(mac,deploy):
    #try : 
        sqlite_select_query = """SELECT * from DecisionUpdate WHERE mac=? LIMIT 1"""
        cursor.execute(sqlite_select_query,(mac,))
        record = cursor.fetchall()
        if not data : 
            print("[i] mac is  : " + mac + "  project is : " + deploy)
            """Download a file."""
            #fetch the right element form database 
            conn = sqlite3.connect('firmware.db')
            cursor = conn.cursor()
            sqlite_select_query = """INSERT INTO DecisionUpdate (mac,deployAs) VALUES (?,?)"""
            cursor.execute(sqlite_select_query,(mac,deploy,))
            conn.commit()
        return "Present SUCCEFULLY"
        
@app.route("/uploadFS/<mac>")
def fileSystemUpdate(mac):
    #try : 
        print("[i] mac is  : " + mac)
        """Download a file."""
        #fetch the right element form database 
        print("[i] Update SPIFFS --> fetch the right record from database")
        conn = sqlite3.connect('firmware.db')
        cursor = conn.cursor()
        sqlite_select_query = """SELECT * from DecisionUpdate WHERE mac=? LIMIT 1"""
        cursor.execute(sqlite_select_query,(mac,))
        record = cursor.fetchall()
        print("[i] Here is : " + str(record[0]))
        if (record[0][3] == "1") : 
            print("[i] allowed to be updated ... FS downloaded SUCCEFULLY") 
            sqlite_select_query = """UPDATE DecisionUpdate SET updateFS=? where mac=?"""
            cursor.execute(sqlite_select_query,("0",mac,))
            conn.commit()
            wantedFile = find(record[0][1],"fileSystem",UPLOAD_DIRECTORY)
            print("[i] the file name is " + str(wantedFile))

            return send_from_directory(UPLOAD_DIRECTORY, wantedFile, as_attachment=True)
        
        else  : 
            print("[i] not allowed to be updated")     
            return "No Update for now"
        
    # except : 
    #     print("[i] not allowed to be updated")    
    #     return "No Update for now"

@app.route("/uploadF/<mac>")
def firmwareUpdate(mac):
   # try : 
        print("[i] mac is  : " + mac)
        """Download a file."""
        #fetch the right element form database 
        print("[i] Update Firmware --> fetch the right record from database")
        conn = sqlite3.connect('firmware.db')
        cursor = conn.cursor()
        sqlite_select_query = """SELECT * from DecisionUpdate WHERE mac=? LIMIT 1"""
        cursor.execute(sqlite_select_query,(mac,))
        record = cursor.fetchall()
        print("[i] Here is : " + str(record[0]))
        if (record[0][2] == "1") : 
            print("[i] allowed to be updated ... F downloaded SUCCEFULLY") 
            sqlite_select_query = """UPDATE DecisionUpdate SET updateF=? where mac=?"""
            cursor.execute(sqlite_select_query,("0",mac,))
            conn.commit()
            wantedFile = find(record[0][1],"firmware",UPLOAD_DIRECTORY)
            print("[i] the file name is " + str(wantedFile))

            return send_from_directory(UPLOAD_DIRECTORY, wantedFile, as_attachment=True)
        
        else  : 
            print("[i] not allowed to be updated")     
            return "No Update for now"
#find file

def find(name,name2, path):
    for root, dirs, files in os.walk(path):
        for file in files : 
            if (name in file ) and (name2 in file) :
                return file
if __name__ == "__main__":

   #app.run(host='0.0.0.0', port=80, debug=False)

    socketio.run(app, host='0.0.0.0', port=8000, log_output=True,threaded=True)        
