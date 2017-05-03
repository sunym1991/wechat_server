#coding=utf-8
from flask import abort, request, Response
from wechatpy.enterprise.crypto import WeChatCrypto
from flask import Flask
import time
import xmltodict
import base64
import requests
from flask import jsonify
import json
import random
import ConfigParser
from party_id import PARTY_ID
config = ConfigParser.RawConfigParser()
config.read('config.ini')
app = Flask(__name__)

crypto = WeChatCrypto(token=config.get('token', 'sToken'), encoding_aes_key=config.get('token', 'sEncodingAESKey'),
                      corp_id=config.get('token', 'sCorp_Id'))


@app.route('/', methods=['POST'])
def weixin():
    signature = request.args['msg_signature']
    timestamp = request.args['timestamp']
    nonce = request.args['nonce']
    xml_content = crypto.decrypt_message(msg=request.get_data(), signature=signature, timestamp=timestamp, nonce=nonce)
    content = xmltodict.parse(xml_content)['xml']
    app.logger.debug(content)
    user_name = content['FromUserName']
    msg_type = content['MsgType']

    if msg_type == 'text':
        msg_content = content['Content']
        forward_message = {
            'content': msg_content,
            'user_id': user_name,
        }
        response = requests.post(url='http://localhost:8999/wechat/text', json=forward_message)
        app.logger.debug(response.json())
        reply_content = response.json()['response']

    if msg_type == 'image':
        msg_content = requests.get(content['PicUrl'])
        forward_message = {
            'content': base64.b64encode(msg_content.content),
            'user_id': user_name,
            'file_name': 'Wechat_{}.png'.format(random.randint(1, 100))
        }
        response = requests.post(url='http://localhost:8999/wechat/file', json=forward_message)
        app.logger.debug(response.json())
        reply_content = response.json()['response']

    message = u"""
<xml>
   <ToUserName><![CDATA[{}]]></ToUserName>
   <FromUserName><![CDATA[wx2a4a6c713327df27]]></FromUserName>
   <CreateTime>{}</CreateTime>
   <MsgType><![CDATA[text]]></MsgType>
   <Content><![CDATA[{}]]></Content>
</xml>
""".format(user_name, int(time.time()), reply_content)
    app.logger.debug(u'response message:{}'.format(message))
    encrypt_message = crypto.encrypt_message(message, nonce)
    app.logger.debug(encrypt_message)
    return Response(encrypt_message, mimetype='text/xml')


@app.route('/send_agent/text', methods=['POST'])
def send_agent_text():
    message = request.json['message']
    user = request.json['user']
    if user == 'all':
        send_content = {
            'touser': '@all',
            'toparty': '1',
            'totag': '1',
            'msgtype': 'text',
            'agentid': 44,
            'text': {
                'content': message
            },
            'safe': 0
        }
    else:
        party_id = PARTY_ID[user]
        send_content = {
            'toparty': party_id,
            'msgtype': 'text',
            'agentid': 44,
            'text': {
                'content': message
            },
            'safe': 0
        }

    data = json.dumps(send_content, ensure_ascii=False).encode('utf8')

    param_token = {
        'corpid': config.get('token', 'corpid'),
        'corpsecret': config.get('token', 'corpsecret')
    }
    response_token = requests.get(url='https://qyapi.weixin.qq.com/cgi-bin/gettoken', params=param_token, verify=False)
    AccessToken = response_token.json()['access_token']
    param = {"access_token": AccessToken}
    response = requests.post(url='https://qyapi.weixin.qq.com/cgi-bin/message/send', params=param, data=data, verify=False)
    app.logger.debug(response.json())
    if response.status_code == 200:
        payload = {'Success': 'false'}
    else:
        payload = {'Success': 'true'}
    return jsonify(payload)


if __name__ == '__main__':
    import logging

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # create file handler
    file_handler = logging.FileHandler('qy_wechat_server.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # create console handler with a higher log level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)

    app.logger.addHandler(console_handler)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.DEBUG)

    app.run(host='0.0.0.0', port=8989)
