import pyotp
import qrcode
import time
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa # public / private
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet # symmetric
import subprocess
import os
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    )
    public_key = private_key.public_key()
    return {'private': private_key, 'public': public_key}

def rsa_encrypt(msg, public_key):
    return public_key.encrypt(
    msg.encode('ascii'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

def rsa_decrypt(msg, private_key):
    dec = private_key.decrypt(
    msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )
    return dec.decode('ascii')

def serialize_publickey(key):
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def unserialize_publickey(pem):
    return serialization.load_pem_public_key(pem)

def generate_key():
    return Fernet.generate_key()

def encrypt_secret(msg, key):
    f = Fernet(key)
    return f.encrypt(msg.encode('ascii')).decode('ascii')

def decrypt_secret(msg, key):
    f = Fernet(key)
    dec = f.decrypt(msg.encode('ascii'))
    return dec.decode('ascii')

def generate_otp(secret, username):
    totp_auth = pyotp.totp.TOTP(secret).provisioning_uri( name=username, issuer_name='Health System')
    return totp_auth

def verify_otp(secret):
    totp = pyotp.TOTP(secret)
    return totp.verify(input(("enter 2fa code: ")))

class system:
    user_accounts = []
    timeouts = []
    sessions = []
    key_pair = {}
    key = {}
    patient_information = []
    precription_info = []
    copayment_info = []
    def __init__(this):
        this.key_pair = generate_rsa_keypair()
        this.key = generate_key()

    def save_data(this):
        save_data = {
            'accounts': this.user_accounts,
            'key': this.key.decode('ascii'),
            'info': this.patient_information,
            'precription': this.precription_info,
            'payment': this.copayment_info
        }
        with open("database.json", 'w') as file:
            json.dump(save_data, file, indent=4)

    def load_data(this):
        with open("database.json", 'r') as file:
            loaded = json.load(file)
            this.user_accounts = loaded['accounts']
            key = str(loaded['key'])
            key = key.encode('ascii')
            this.key = key
            this.patient_information = loaded['info']
            this.precription_info = loaded['precription']
            this.copayment_info = loaded['payment']

    def reset_data(this):
        this.user_accounts = []
        this.key_pair = generate_rsa_keypair()
        this.key = generate_key()
        this.patient_information = []
        os.remove('database.json')

    def get_public_key(this):
        return this.key_pair['public']
    
    def get_doctors(this):
        doctor_names = []
        for enc_account in this.user_accounts:
            dec = decrypt_secret(enc_account, this.key)
            account = json.loads(dec)
            if (account['perms'] == 'doctor'):
                doctor_names.append(account['name'])
        return doctor_names
    
    def get_insurance(this):
        doctor_names = []
        for enc_account in this.user_accounts:
            dec = decrypt_secret(enc_account, this.key)
            account = json.loads(dec)
            if (account['perms'] == 'insurance company'):
                doctor_names.append(account['name'])
        return doctor_names
    
    def get_patients(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'patients': []
        }
        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)

        for enc_info in this.patient_information:
            dec = decrypt_secret(enc_info, this.key)
            info = json.loads(dec)
            if (info['doctor'] == msg['name']):
                obj = {}
                obj['name'] = (info['name'])
                obj['ssn'] = (info['ssn'])
                request['patients'].append(obj)
        request['type'] = 'SUCCESS'
        request['msg'] = 'got patient names'
        return rsa_encrypt(json.dumps(request), public_key)
    
    def get_patients_insurance(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'patients': []
        }
        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)

        for enc_info in this.patient_information:
            dec = decrypt_secret(enc_info, this.key)
            info = json.loads(dec)
            if (info['insurance'] == msg['name']):
                obj = {}
                obj['name'] = (info['name'])
                obj['ssn'] = (info['ssn'])
                obj['notes'] = (info['notes'])
                request['patients'].append(obj)
        request['type'] = 'SUCCESS'
        request['msg'] = 'got patient names'
        return rsa_encrypt(json.dumps(request), public_key)
    
    def approve_copay(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
        }
        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for enc_info in this.patient_information:
            dec = decrypt_secret(enc_info, this.key)
            info = json.loads(dec)
            if (info['insurance'] == msg['name'] and info['name'] == msg['patient']):

                info_str = json.dumps(msg['copay'])
                this.copayment_info.append(encrypt_secret(info_str, this.key))

                request['type'] = 'SUCCESS'
                request['msg'] = 'updated copay information'
                request['info'] = info
                return rsa_encrypt(json.dumps(request), public_key)
            
        request['type'] = 'ERROR'
        request['msg'] = 'invalid patient or permissions'
        return rsa_encrypt(json.dumps(request), public_key)
    
    def get_copay(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'amount': '',
        }
        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for enc_info in this.copayment_info:
            dec = decrypt_secret(enc_info, this.key)
            info = json.loads(dec)
            if ( info['name'] == msg['name'] and info['ssn'] == msg['ssn'] ):
                request['type'] = 'SUCCESS'
                request['msg'] = 'updated copay information'
                request['amount'] = info['amount']
                return rsa_encrypt(json.dumps(request), public_key)
            
        request['type'] = 'ERROR'
        request['msg'] = 'invalid patient or permissions'
        return rsa_encrypt(json.dumps(request), public_key)

    def login(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
        }

        if (msg['type'] != 'login'):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for enc_account in this.user_accounts:
            dec = decrypt_secret(enc_account, this.key)
            account = json.loads(dec)
            if account['user_id'] == msg['user_id']:
                request['type'] = '2FA'
                request['msg'] = 'please enter your 2fa code within 2 minutes: '
                this.timeouts.append({'user': account['user_id'], 'time': time.time() + 120.0})
                return rsa_encrypt(json.dumps(request), public_key)
        request['type'] = 'ERROR'
        request['msg'] = 'invalid user or password'
        return rsa_encrypt(json.dumps(request), public_key)  

    def validate_2fa(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
        }

        if ( msg['type'] != '2fa'):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for timeout in this.timeouts:
            if timeout['user'] == msg['user_id']:
                if time.time() > timeout['time']:
                    request['type'] = 'ERROR'
                    request['msg'] = '2fa timeout expired'
                    this.timeouts.remove(timeout)
                    return rsa_encrypt(json.dumps(request), public_key)
                
                for enc_account in this.user_accounts:
                    dec = decrypt_secret(enc_account, this.key)
                    account = json.loads(dec)
                    if account['user_id'] == msg['user_id']:
                        otp = pyotp.TOTP(account['secret'])
                        if otp.verify(msg['2fa']):
                            if account['password'] == msg['password']:
                                request['type'] = 'SUCCESS'
                                request['msg'] = 'account: ' + msg['user_id'] + ' logged in successfully'
                                this.timeouts.remove(timeout)
                                this.sessions.append({'user': account['user_id'], 'logged_in': True, 'login_time': time.time()})
                                return rsa_encrypt(json.dumps(request), public_key)
                            else:
                                request['type'] = 'ERROR'
                                request['msg'] = 'invalid user or password'
                                this.timeouts.remove(timeout)
                                return rsa_encrypt(json.dumps(request), public_key)
                        else:
                            request['type'] = 'ERROR'
                            request['msg'] = 'invalid 2fa code'
                            this.timeouts.remove(timeout)
                            return rsa_encrypt(json.dumps(request), public_key)
                
        request['type'] = 'ERROR'
        request['msg'] = 'no 2fa request found'
        return rsa_encrypt(json.dumps(request), public_key)

    def logout(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'secret': ''
        }

        if (msg['type'] != 'logout'):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                this.sessions.remove(session)
                request['type'] = 'SUCCESS'
                request['msg'] = 'logged out successfully'
                return rsa_encrypt(json.dumps(request), public_key)
        request['type'] = 'ERROR'
        request['msg'] = 'no session found'
        return rsa_encrypt(json.dumps(request), public_key)

    def create_account(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'secret': ''
        }

        if (msg['type'] != 'create_account'):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)

        for enc_account in this.user_accounts:
            dec = decrypt_secret(enc_account, this.key)
            account = json.loads(dec)
            if account['user_id'] == msg['user_id']:
                request['type'] = 'ERROR'
                request['msg'] = 'invalid username'
                return rsa_encrypt(json.dumps(request), public_key)
        secret = pyotp.random_base32()
        account = {
            'user_id': msg['user_id'],
            'name':    msg['name'],
            'ssn':     msg['ssn'],
            'password': msg['password'],
            'secret': secret,
            'perms': msg['permissions'],
        }
        acct_str = json.dumps(account)
        this.user_accounts.append(encrypt_secret(acct_str, this.key))

        request['type'] = 'SUCCESS'
        request['msg'] = 'account: ' + msg['user_id'] + ' created successfully'
        request['secret'] = secret
        return rsa_encrypt(json.dumps(request), public_key)
    
    def get_patient_info(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'info': {}
        }
        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for enc_info in this.patient_information:
            dec = decrypt_secret(enc_info, this.key)
            info = json.loads(dec)
            if (info['doctor'] == msg['name'] and info['name'] == msg['patient']):
                request['type'] = 'SUCCESS'
                request['msg'] = 'found patient information'
                request['info'] = info
                return rsa_encrypt(json.dumps(request), public_key)
            
        request['type'] = 'ERROR'
        request['msg'] = 'invalid patient or permissions'
        return rsa_encrypt(json.dumps(request), public_key)
    
    def get_patient_info_pharmacy(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'info': {}
        }
        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for enc_info in this.patient_information:
            dec = decrypt_secret(enc_info, this.key)
            info = json.loads(dec)
            if (info['name'] == msg['patient'] and info['ssn'] == msg['ssn']):
                request['type'] = 'SUCCESS'
                request['msg'] = 'found patient information'
                request['info'] = {'name': info['name'], 'ssn': info['ssn'], 'medication': info['medication'], 'doctor': info['doctor']}
                return rsa_encrypt(json.dumps(request), public_key)
            
        request['type'] = 'ERROR'
        request['msg'] = 'invalid patient or permissions'
        return rsa_encrypt(json.dumps(request), public_key)
    
    def update_prescription(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
        }

        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        info_str = json.dumps(msg['prescription'])
        this.precription_info.append(encrypt_secret(info_str, this.key))
        request['type'] = 'SUCCESS'
        request['msg'] = 'updated prescription info'
        return rsa_encrypt(json.dumps(request), public_key)

    def update_patient_chart(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
           'info': {}
        }
        logged_in = False
        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                logged_in = True

        if ( logged_in == False ):
            request['type'] = 'ERROR'
            request['msg'] = 'invalid request'
            return rsa_encrypt(json.dumps(request), public_key)
        
        for i, enc_info in enumerate(this.patient_information):
            dec = decrypt_secret(enc_info, this.key)
            info = json.loads(dec)
            if (info['doctor'] == msg['name'] and info['name'] == msg['patient']):
                if ( msg.get('notes')):
                    if (info.get('notes')):
                        info['notes'].append(msg['notes'])
                    else:
                        info['notes'] = []
                        info['notes'].append(msg['notes'])
                if ( msg.get('medication')):
                    if (info.get('medication')):
                        info['medication'].append(msg['medication'])
                    else:
                        info['medication'] = []
                        info['medication'].append(msg['medication'])
                info_str = json.dumps(info)
                this.patient_information[i] = encrypt_secret(info_str, this.key)
                request['type'] = 'SUCCESS'
                request['msg'] = 'updated patient information'
                request['info'] = info
                return rsa_encrypt(json.dumps(request), public_key)
            
        request['type'] = 'ERROR'
        request['msg'] = 'invalid patient or permissions'
        return rsa_encrypt(json.dumps(request), public_key)

    def set_patient_info(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
        }

        for session in this.sessions:
            if session['user'] == msg['user_id'] and session['logged_in']:
                for i, enc_info in enumerate(this.patient_information):
                    dec = decrypt_secret(enc_info, this.key)
                    info = json.loads(dec)
                    if info['user_id'] == msg['user_id']:
                        info['name'] = msg['name']
                        info['ssn'] = msg['ssn']
                        info['birthday'] = msg['birthday']
                        info['doctor'] = msg['doctor']
                        info['insurance'] = msg['insurance']
                        info_str = json.dumps(info)
                        this.patient_information[i] = encrypt_secret(info_str, this.key)
                        request['type'] = 'SUCCESS'
                        request['msg'] = 'set patient information'
                        return rsa_encrypt(json.dumps(request), public_key)
                #info doesnt exist yet
                info = {}
                info['user_id'] = msg['user_id']
                info['name'] = msg['name']
                info['ssn'] = msg['ssn']
                info['birthday'] = msg['birthday']
                info['doctor'] = msg['doctor']
                info['insurance'] = msg['insurance']
                info['medication'] = ['']
                info['notes'] = ['']
                info_str = json.dumps(info)
                enc_info = encrypt_secret(info_str, this.key)
                this.patient_information.append(enc_info)
                request['type'] = 'SUCCESS'
                request['msg'] = 'set patient information'
                return rsa_encrypt(json.dumps(request), public_key)

                
                    

        request['type'] = 'ERROR'
        request['msg'] = 'no session found'
        return rsa_encrypt(json.dumps(request), public_key)


class user:
    user_id = ""
    password = ""
    key_pair = {}
    secret = ""
    actor_type = ""
    name = ""
    ssn = ""
    session_active = False
    def __init__(this, username, password, name, ssn, actor_type, secret):
        this.key_pair = generate_rsa_keypair()
        this.user_id = username
        this.password = password
        this.name = name
        this.ssn = ssn
        this.actor_type = actor_type
        this.secret = secret

    def serialize(this):
        return {
            'user': this.user_id,
            'password': this.password,
            'actor_type': this.actor_type,
            'secret': this.secret,
            'name': this.name,
            'ssn': this.ssn
        }

    def login(this, system: system):
        request = {
            'type': 'login',
            'user_id': this.user_id,
            'password': this.password,
            '2fa': ''
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.login(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != '2FA'):
            print("ERROR logging into account: " + out['msg'])
            return False
        
        request['2fa'] = input(out['msg'])
        request['type'] = '2fa'
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.validate_2fa(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR logging into account: " + out['msg'])
            return False
        
        print("SUCCESS " + out['msg'])
        this.session_active = True
        return True
    
    def logout(this, system: system):
        if this.session_active == False:
            return True
        request = {
            'type': 'logout',
            'user_id': this.user_id,
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.logout(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR logging out of account: " + out['msg'])
            return False
        
        print("SUCCESS: " + out['msg'])
        this.session_active = False
        return True

    def create_account(this, system: system):
        request = {
            'type': 'create_account',
            'user_id': this.user_id,
            'password': this.password,
            'name': this.name,
            'ssn': this.ssn,
            'permissions': this.actor_type
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.create_account(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR creating account: " + out['msg'])
            return False
        
        if ( out['type'] == 'SUCCESS'):
            this.secret = out['secret']
            otp = generate_otp(this.secret, this.user_id)
            qrcode.make(otp).save(this.user_id + ".png")
            subprocess.run(["start", this.user_id + ".png"], shell=True)
            print(out['msg'])
            return True
        print("ERROR creating account")
        return False

    
class bank:
    key_pair = []
    balance = 0
    def __init__(this):
        this.key_pair = generate_rsa_keypair()
        this.balance = 10000

    def get_public_key(this):
        return this.key_pair['public']
    
    def process_payment(this, enc_msg, public_key):
        msg = rsa_decrypt(enc_msg, this.key_pair['private'])
        msg = json.loads(msg)
        request = {
           'type': '',
           'msg': '',
        }

        amount = int(msg['amount'])

        if ( amount > this.balance ):
            request['type'] = 'ERROR'
            request['msg'] = 'insufficent balance'
            return rsa_encrypt(json.dumps(request), public_key)
        
        this.balance -= amount

        request['type'] = 'SUCCESS'
        request['msg'] = 'balance paid successfully'
        return rsa_encrypt(json.dumps(request), public_key)




class Patient(user):
    def __init__(this, user: user):
        this.key_pair = user.key_pair
        this.user_id = user.user_id
        this.password = user.password
        this.actor_type = user.actor_type
        this.secret = user.secret
        this.ssn = user.ssn
        this.name = user.name

    def set_information(this, birthday, doctor, insurance, system: system):
        request = {
            'type': 'set_patient_info',
            'user_id': this.user_id,
            'name': this.name,
            'birthday': birthday,
            'ssn': this.ssn,
            'doctor': doctor,
            'insurance' : insurance
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.set_patient_info(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR setting patient information: " + out['msg'])
            return False
        print("SUCCESS " + out['msg'])
        return True
    
    def pay_bill(this, card_info, system : system, bank : bank):
        request = {
            'user_id': this.user_id,
            'name': this.name,
            'ssn': this.ssn,
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.get_copay(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR getting copay amount: " + out['msg'])
            return False
        
        payment_request = {
            'card_info': card_info,
            'amount': out['amount']
        }
        msg = rsa_encrypt(json.dumps(payment_request), bank.get_public_key())
        bank.process_payment(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR with payment: " + out['msg'])
            return False
        print("SUCCESS: paid for copay successfully")
        return True
        



def patient_menu(logged_in : user, health_system : system, the_bank : bank):
    patient = Patient(logged_in)
    while (True):
        print("1. set patient information")
        print("2. pay bill")
        print("3. logout")
        action = int(input ('action: '))
        if ( action == 1 ):
            birthday = input('Birthday: ')
            doctors_list = health_system.get_doctors()
            doctor = ""
            while ( True ):
                print("select doctor:")
                for i in range(len(doctors_list)):
                    doctor = doctors_list[i]
                    print(str(i) + ':' + ' Dr. ' + doctor)
                i = int(input("Doctor id: "))
                if ( i < 0 or i > (len(doctors_list) - 1)):
                    print("invalid doctor input")
                    continue
                doctor = doctors_list[i]
                break
            insurance_list = health_system.get_insurance()
            insurance = ""
            while ( True ):
                print("select insurance company:")
                for i in range(len(insurance_list)):
                    insurance = insurance_list[i]
                    print(str(i) + ': ' + insurance)
                i = int(input("insurance company id: "))
                if ( i < 0 or i > (len(insurance_list) - 1)):
                    print("invalid insurance company input")
                    continue
                insurance = insurance_list[i]
                break
            patient.set_information(birthday, doctor, insurance, health_system)
        elif ( action == 2 ):
            card_info = input('credit card number: ')
            patient.pay_bill(card_info, health_system, the_bank)
        elif ( action == 3 ):
            logged_in.logout(health_system)
            break
        else:
            print("invalid action")

class Doctor(user):
    def __init__(this, user: user):
        this.key_pair = user.key_pair
        this.user_id = user.user_id
        this.password = user.password
        this.actor_type = user.actor_type
        this.secret = user.secret
        this.ssn = user.ssn
        this.name = user.name

    def get_patients(this, system : system):
        request = {
            'user_id': this.user_id,
            'name': this.name,
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.get_patients(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        
        if ( out['type'] != 'SUCCESS'):
            print("ERROR getting patients: " + out['msg'])
            return []

        return out['patients']




    def treat_patient(this, patient, system : system):
        request = {
            'user_id': this.user_id,
            'name': this.name,
            'patient': patient['name']
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.get_patient_info(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)

        if ( out['type'] != 'SUCCESS'):
            print("ERROR getting patient info: " + out['msg'])
            return False
        
        print("patient info: ")
        print(out['info'])

        update_info = False
        notes = input("do you need to include a treatment note? y/n: ")
        if (notes == 'y'):
            update_info = True
            request['notes'] = input("treatment note: ")

        medication = input('do you need to update any medications? y/n: ')

        if ( medication == 'y'):
            update_info = True
            request['medication'] = input("medications: ")

        if ( update_info ):
            msg = rsa_encrypt(json.dumps(request), system.get_public_key())
            enc_out = system.update_patient_chart(msg, this.key_pair['public'])
            out = rsa_decrypt(enc_out, this.key_pair['private'])
            out = json.loads(out)
            if ( out['type'] != 'SUCCESS'):
                print("ERROR getting patient info: " + out['msg'])
                return False
            print("updated patient information successfully. new information:")
            print(out['info'])
        
        return True


def doctor_menu(logged_in : user, health_system : system):
    doctor = Doctor(logged_in)
    while (True):
        print("1. treat patient")
        print("2. logout")
        action = int(input ('action: '))
        if ( action == 1 ):
            patients = doctor.get_patients(health_system)
            for i in range(len(patients)):
                patient = patients[i]
                print(str(i) + ": " + patient['name'] + " ssn: " + patient['ssn'])
            id = -1
            while (True):
                id = int(input("Select patient number: "))
                if ( id < 0 or id > (len(patients) - 1) ):
                    print("invalid patient")
                    continue
                break
            doctor.treat_patient(patients[id], health_system)
        elif ( action == 2):
            logged_in.logout(health_system)
            break
        else:
            print("invalid action")
        continue


class Pharmacist(user):
    def __init__(this, user: user):
        this.key_pair = user.key_pair
        this.user_id = user.user_id
        this.password = user.password
        this.actor_type = user.actor_type
        this.secret = user.secret
        this.ssn = user.ssn
        this.name = user.name

    def request_patient_info(this, patient, ssn, system : system):
        request = {
            'user_id': this.user_id,
            'name': this.name,
            'patient': patient,
            'ssn': ssn
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.get_patient_info_pharmacy(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR getting patient info: " + out['msg'])
            return False
        print(out['info'])
        return out['info']

    def fill_script(this, patient, birthday, ssn, medication, system : system):
        request = {
            'user_id': this.user_id,
            'prescription': { 'pharmacist': this.name, 'patient': patient, 'ssn': ssn, 'birthday': birthday, 'time': time.time(), 'medication': medication}
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.update_prescription(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        if ( out['type'] != 'SUCCESS'):
            print("ERROR filling prescription: " + out['msg'])
            return False
        print(out)


def pharmacy_menu(logged_in : user, health_system : system):
    pharmacist = Pharmacist(logged_in)
    while (True):
        print("1. fill script")
        print("2. logout")
        action = int(input ('action: '))
        if ( action == 1 ):
            name = input("Patient Name: ")
            ssn = input("Patient SSN: ")
            info = pharmacist.request_patient_info(name, ssn, health_system)
            if ( info == False ):
                continue
            birthday = input("Patient birthday: ")
            pharmacist.fill_script(name, birthday, ssn, info['medication'], health_system)
        elif ( action == 2):
            logged_in.logout(health_system)
            break
        else:
            print("invalid action")
        continue

class Insurace(user):
    def __init__(this, user: user):
        this.key_pair = user.key_pair
        this.user_id = user.user_id
        this.password = user.password
        this.actor_type = user.actor_type
        this.secret = user.secret
        this.ssn = user.ssn
        this.name = user.name

    def get_patients(this, system : system):
        request = {
            'user_id': this.user_id,
            'name': this.name,
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.get_patients_insurance(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        
        if ( out['type'] != 'SUCCESS'):
            print("ERROR getting patients: " + out['msg'])
            return []

        return out['patients']
    
    def approve_copay(this, amount, patient, ssn, system : system):
        request = {
            'user_id': this.user_id,
            'name': this.name,
            'patient': patient,
            'ssn' : ssn,
            'copay': {'name': patient, 'ssn': ssn, 'amount': amount, 'insurance': this.name, 'paid': False}
        }
        msg = rsa_encrypt(json.dumps(request), system.get_public_key())
        enc_out = system.approve_copay(msg, this.key_pair['public'])
        out = rsa_decrypt(enc_out, this.key_pair['private'])
        out = json.loads(out)
        
        if ( out['type'] != 'SUCCESS'):
            print("ERROR getting patients: " + out['msg'])
            return False
        
        print("SUCCESS" + out['msg'])


def insurance_menu(logged_in : user, health_system : system):
    insurance = Insurace(logged_in)
    while (True):
        print("1. approve copay")
        print("2. logout")
        action = int(input ('action: '))
        if ( action == 1 ):
            patients = insurance.get_patients(health_system)
            for i in range(len(patients)):
                patient = patients[i]
                print(str(i) + ": " + patient['name'] + " ssn: " + patient['ssn'])
                print('notes: ')
                print(patient['notes'])
            id = -1
            while (True):
                id = int(input("Select patient number: "))
                if ( id < 0 or id > (len(patients) - 1) ):
                    print("invalid patient")
                    continue
                break
            copay_amount = input("copay amount: ")
            selected_patient = patients[id]
            insurance.approve_copay(copay_amount, selected_patient['name'], selected_patient['ssn'], health_system)
        elif ( action == 2):
            logged_in.logout(health_system)
            break
        else:
            print("invalid action")
        continue


def main():
    health_system = system()
    the_bank = bank()
    users = []
    while True:
        print("health system test application:")
        print("1. create account")
        print("2. login to account")
        print("3. load database")
        print("4. save database")
        print("5. reset database")
        print("6. exit")
        choice = int(input("pick an option to continue: "))
        if choice == 1:
            print("Enter account info:")
            username = input('username: ')
            password = input('password: ')
            name = input('Name: ')
            ssn = input("ssn: ")
            print("enter type: 0 patient, 1 doctor, 2 pharmacist, 3 insurance company, 4 researcher")
            type = int(input('type: '))
            permissions = ""
            if type == 0:
                permissions = 'patient'
            elif type == 1:
                permissions = 'doctor'
            elif type == 2:
                permissions = 'pharmacist'
            elif type == 3:
                permissions = 'insurance company'
            elif type == 4:
                permissions = 'researcher'
            else:
                print("invalid type specified, try again")
                continue
            new_user = user(username, password, name, ssn, permissions, '')
            if new_user.create_account(health_system):
                users.append(new_user)
        elif choice == 2:
            print("enter account info:")
            username = input('username: ')
            password = input('password: ')
            logged_in = user
            
            for account in users:
                if account.user_id == username:
                    old_pass = account.password
                    account.password = password
                    if account.login(health_system):
                        logged_in = account
                        break
                    account.password = old_pass

            if len(logged_in.user_id):
                if (logged_in.actor_type == 'patient'):
                    patient_menu(logged_in, health_system, the_bank)
                elif (logged_in.actor_type == 'doctor'):
                    doctor_menu(logged_in, health_system)
                elif (logged_in.actor_type == 'pharmacist'):
                    pharmacy_menu(logged_in, health_system)
                elif (logged_in.actor_type == 'insurance company'):
                    insurance_menu(logged_in, health_system)
                else:
                    logged_in.logout()
            else: 
                print("ERROR: invalid login")


        elif choice == 3:
            print("loading database from file...")
            health_system.load_data()
            users = []
            with open('menu_users.json', 'r') as file:
                serialized_data_list = json.load(file)
                for data in serialized_data_list:
                    new_user = user(data['user'], data['password'], data['name'], data['ssn'], data['actor_type'], data['secret'])
                    users.append(new_user)
        elif choice == 4:
            print("saving database to file...")
            health_system.save_data()
            serialized_data_list = [obj.serialize() for obj in users]
            with open('menu_users.json', 'w') as file:
                 json.dump(serialized_data_list, file, indent=4)
        elif choice == 5:
            print("resetting database..")
            health_system.reset_data
        elif choice == 6:
            exit()
        else:
            print("invalid choice try again.")
    





if __name__ == '__main__':
    main()