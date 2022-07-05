from django.conf import settings
import requests
import datetime
from Crypto.Cipher import AES
import base64
import json
import hashlib
import time
import hmac


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]
secret_key  = settings.EASY_PAISA_SECRET_KEY

def calculate_secure_hash(payload):
    payload_values = ["{}=".format(key)+payload[key] for key in sorted(payload.keys()) if payload[key] and key != 'merchantHashedReq']
    string_to_hash = f"{'&'.join(payload_values)}"
    raw = pad(string_to_hash)
    cipher = AES.new(secret_key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(raw)) 

def generate_easy_paisa_token(request,total,order_number,bank):
    user = request.user
    now = datetime.datetime.now()
    expire_time = (now + datetime.timedelta(minutes=5)).strftime("%Y%m%d %H%M%S")
    
    values = {
        'storeId' : settings.EASY_PAISA_STORE_ID,
        'amount' : "{:.1f}".format(total),
        'postBackURL' : "https://www.test.com/confirmPayment.php",
        'orderRefNum' : order_number,
        'expiryDate' : expire_time,
        'autoRedirect' : '0',
        'paymentMethod' : 'CC_PAYMENT_METHOD',
        'emailAddr' : str(user.email),
        'mobileNum' : str(user.phone_number).replace('+92','0').replace('-',''),
        'merchantHashedReq':''
    }
    
    

    headers = {
        'User-Agent': 'python',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    z = calculate_secure_hash(values).decode('utf-8')
    values['merchantHashedReq'] = z
    if bank:
        values['bankIdentificationNumber'] = bank.bank_unique_code
    

    try:
        r = requests.post('https://easypaystg.easypaisa.com.pk/easypay/Index.jsf',data=values,headers=headers).url
    except requests.exceptions.ConnectionError:
        r =""
        print("exception")
    
    return r.split('auth_token=')[1].split('&postBackURL=')[0]

integerity_salt = str(settings.JAZZ_CASH_INTEGERIY_SALT)
merchant_id = str(settings.JAZZ_CASH_MERCHANT_ID)
password = str(settings.JAZZ_CASH_PASSWORD)

def calculate_secure_hash_jazz(payload):
    shared_secret = integerity_salt 
    payload_values = [payload[key] for key in sorted(payload.keys()) if payload[key] and key != 'pp_SecureHash']
    
    string_to_hash = f"{shared_secret}&{'&'.join(payload_values)}"
    print(string_to_hash)
    secure_hash = hmac.new(
        shared_secret.encode('utf-8'),
        string_to_hash.encode('ISO-8859-1'),
        hashlib.sha256
    ).hexdigest().upper()
    
    return secure_hash

def process_jazz_cash(total,order_id):
    now = datetime.datetime.now()
    transaction_id = 'T'+ now.strftime("%Y%m%d%H%M%S")
    expire_time = (now + datetime.timedelta(hours=24)).strftime("%Y%m%d%H%M%S")

    payload = {
        "pp_Version": "1.1",
        "pp_TxnType": "",
        "pp_Language":"EN",
        "pp_TxnRefNo": transaction_id,
        "pp_MerchantID": merchant_id,
        "pp_SubMerchantID":"",
        "pp_Password": password,
        "pp_BankID":"TBANK",
        "pp_ProductID":"RETL",
        "pp_Amount": str(int(total*100)),
        "pp_TxnCurrency": "PKR",
        "pp_TxnExpiryDateTime": expire_time,
        "pp_BillReference": order_id,
        "pp_Description": "Payment On your Ecommerce",
        "pp_SecureHash": "",
        "pp_TxnDateTime": now.strftime("%Y%m%d%H%M%S"),
        "pp_ReturnURL":"https://dev.youwe.pk/?wc-api=jazzcashresponse",
        "ppmpf_1":"1",
        "ppmpf_2":"2",
        "ppmpf_3":"3",
        "ppmpf_4":"4",
        "ppmpf_5":"5",
    }
    payload['pp_SecureHash'] = calculate_secure_hash_jazz(payload).lower()
    return payload

