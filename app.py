from flask import Flask, request, jsonify, render_template_string, session
import requests
import json
import time
import random
import string
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import secrets
from urllib.parse import quote
import uuid

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Random secret key for session management

DEFAULT_APPID = "2f8af12ad9912d306b5053abf90c7ebbb695887bc870ae0706d573c348539c26c5c0a878641fcc0d3e90acb9be1e6ef858a59af546f3c826988332376b7d18c8ea2398ee3a9c3db947e2471d32a49612"

# ================= RSA 加密 =================

class Encrypt:
    def __init__(self):
        self.public_key = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc+CZK9bBA9IU+gZUOc6FUGu7y
O9WpTNB0PzmgFBh96Mg1WrovD1oqZ+eIF4LjvxKXGOdI79JRdve9NPhQo07+uqGQ
gE4imwNnRx7PFtCRryiIEcUoavuNtuRVoBAm6qdB0SrctgaqGfLgKvZHOnwTjyNq
jBUxzMeQlEC2czEMSwIDAQAB
-----END PUBLIC KEY-----"""

    def rsa(self, data):
        try:
            if not data:
                return ""
            
            # Load the public key
            rsa_key = RSA.import_key(self.public_key)
            cipher = PKCS1_v1_5.new(rsa_key)
            
            # Encrypt data in chunks (max 117 bytes for 1024-bit key)
            chunk_size = 117
            encrypted_chunks = []
            
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                encrypted_chunk = cipher.encrypt(chunk)
                encrypted_chunks.append(encrypted_chunk)
            
            # Combine all encrypted chunks and encode as base64
            encrypted_data = b''.join(encrypted_chunks)
            return base64.b64encode(encrypted_data).decode('utf-8')
        
        except Exception as e:
            print(f"RSA encryption error: {e}")
            return ""


# ================= 核心登录类 =================

class UnicomAndroid:
    def __init__(self, phone, appid, default_appid, device_id=""):
        self.phone = phone
        self.encrypt = Encrypt()
        self.device_id = device_id if device_id else self._generate_device_id()
        
        # Use provided appid if valid, otherwise use default
        self.appid = appid if appid and len(appid) > 20 else default_appid
        
        self.ua = (
            "Mozilla/5.0 (Linux; Android 13; M2007J3SC Build/TKQ1.220829.002; wv) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/107.0.5304.141 Mobile Safari/537.36; "
            f"unicom{{version:android@11.0800,desmobile:{phone}}};"
            "devicetype{deviceBrand:Xiaomi,deviceModel:M2007J3SC};{yw_code:}"
        )

    def _generate_device_id(self):
        """Generate a 32-character hex device ID"""
        return ''.join(random.choices('0123456789abcdef', k=32))

    def _post(self, url, data):
        """Send POST request with proper headers"""
        try:
            headers = {
                "Host": "m.client.10010.com",
                "User-Agent": self.ua,
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "com.sinovatech.unicom.ui"
            }
            
            response = requests.post(url, data=data, headers=headers, timeout=15)
            
            try:
                json_response = response.json()
                return json_response
            except ValueError:
                return {"code": "Err", "msg": "HTML 响应(IP 可能被风控)"}
                
        except requests.exceptions.RequestException as e:
            return {"code": "Err", "msg": f"请求异常: {str(e)}"}
        except Exception as e:
            return {"code": "Err", "msg": "请求异常"}

    def _post_json(self, url, data, extra_headers=None):
        """Send POST request with JSON data"""
        try:
            headers = {
                "Content-Type": "application/json",
                "X-Requested-With": "com.sinovatech.unicom.ui"
            }
            
            if extra_headers:
                headers.update(extra_headers)
            
            response = requests.post(url, json=data, headers=headers, timeout=15)
            
            try:
                json_response = response.json()
                return json_response
            except ValueError:
                return {"code": "Err", "msg": "HTML 响应(IP 可能被风控)"}
                
        except requests.exceptions.RequestException as e:
            return {"code": "Err", "msg": f"请求异常: {str(e)}"}
        except Exception as e:
            return {"code": "Err", "msg": "请求异常"}

    def login(self, code):
        """Perform login with phone and code"""
        url = "https://m.client.10010.com/mobileService/radomLogin.htm"
        timestamp = time.strftime("%Y%m%d%H%M%S")

        mobile = quote(self.encrypt.rsa(self.phone))
        pwd = quote(self.encrypt.rsa(code))

        post_data = (
            f"isFirstInstall=1"
            f"&simCount=1"
            f"&yw_code="
            f"&loginStyle=0"
            f"&isRemberPwd=true"
            f"&deviceOS=android13"
            f"&mobile={mobile}"
            f"&netWay=Wifi"
            f"&version=android@11.0800"
            f"&deviceId={self.device_id}"
            f"&password={pwd}"
            f"&keyVersion="
            f"&provinceChanel=general"
            f"&appId={self.appid}"
            f"&deviceModel=M2007J3SC"
            f"&androidId={self.device_id[:16]}"
            f"&deviceBrand=Xiaomi"
            f"&timestamp={timestamp}"
        )

        res = self._post(url, post_data)

        if "code" in res and str(res["code"]) in ["0", "0000"]:
            full_result = f"{self.phone}#{code}#{res.get('token_online', '')}#{res.get('ecs_token', '')}#{self.appid}"
            return {
                "status": "success",
                "full": full_result
            }

        return {
            "status": "fail",
            "msg": f"登录失败: {res.get('desc', '未知错误')} [Code:{res.get('code', '')}]"
        }

    def validate_tencent_captcha(self, mobile_hex, ticket, rand_str):
        """Validate Tencent CAPTCHA"""
        url = "https://loginxhm.10010.com/login-web/v1/chartCaptcha/validateTencentCaptcha"
        payload = {
            "seq": ''.join(random.choices('0123456789abcdef', k=32)),
            "captchaType": "10",
            "mobile": mobile_hex,
            "ticket": ticket,
            "randStr": rand_str,
            "imei": self.device_id
        }

        headers = [
            "Origin: https://img.client.10010.com",
            "Referer: https://img.client.10010.com/loginRisk/index.html"
        ]

        # Format headers properly for the request
        formatted_headers = {
            "Origin": "https://img.client.10010.com",
            "Referer": "https://img.client.10010.com/loginRisk/index.html"
        }

        return self._post_json(url, payload, formatted_headers)

    def send_code(self, result_token=""):
        """Send SMS verification code"""
        url = "https://m.client.10010.com/mobileService/sendRadomNum.htm"
        timestamp = time.strftime("%Y%m%d%H%M%S")

        mobile = quote(self.encrypt.rsa(self.phone))
        rt = quote(result_token) if result_token else ""

        post_data = (
            f"isFirstInstall=1"
            f"&simCount=1"
            f"&yw_code="
            f"&deviceOS=android13"
            f"&mobile={mobile}"
            f"&netWay=Wifi"
            f"&loginCodeLen=6"
            f"&deviceId={self.device_id}"
            f"&deviceCode={self.device_id}"
            f"&version=android@11.0800"
            f"&send_flag="
            f"&resultToken={rt}"
            f"&keyVersion="
            f"&provinceChanel=general"
            f"&appId={self.appid}"
            f"&deviceModel=M2007J3SC"
            f"&androidId={self.device_id[:16]}"
            f"&deviceBrand=Xiaomi"
            f"&timestamp={timestamp}"
        )

        res = self._post(url, post_data)

        # Check for success status
        ok = False
        if "code" in res and str(res["code"]) in ["0", "0000"]:
            ok = True
        if "rsp_code" in res and str(res["rsp_code"]) == "0000":
            ok = True
        if "status" in res and str(res["status"]) == "success":
            ok = True

        if ok:
            return {"status": "success", "msg": "验证码已发送", "data": res}

        msg = res.get("msg", res.get("desc", res.get("rsp_desc", "发送失败")))
        return {"status": "fail", "msg": f"发送失败: {msg}", "data": res}


# ================= 登录接口 =================

@app.route('/')
def index():
    """Serve the main HTML page"""
    html_template = '''
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>联通 Token 在线获取助手(短信版)</title>
<script src="https://turing.captcha.qcloud.com/TJCaptcha.js"></script>

<style>
body{font-family:'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;padding-top:30px}
.box{background:#fff;padding:25px;border-radius:12px;width:100%;max-width:420px;box-shadow:0 6px 20px rgba(0,0,0,0.08)}
h3{text-align:center;color:#333;margin-bottom:20px;font-weight:600}
.tip{font-size:13px;color:#555;background:#f8f9fa;padding:12px;border-radius:6px;border-left:4px solid #007bff;margin-bottom:20px;line-height:1.6}
.notice{background:#fff7e6;border:1px solid #ffe0b2;border-radius:8px;padding:12px 12px 10px;margin:8px 0 16px}
.notice-title{font-weight:700;color:#7a4a00;margin-bottom:6px}
.notice-text{font-size:13px;color:#6b4b16;line-height:1.6}
input{width:100%;padding:12px;margin-bottom:12px;border:1px solid #ddd;border-radius:6px;box-sizing:border-box}
.ph-wrap{position:relative}
.ph-suggest{position:absolute;left:0;right:0;top:46px;background:#fff;border:1px solid #ddd;border-radius:6px;box-shadow:0 6px 16px rgba(0,0,0,0.08);z-index:10;display:none;max-height:200px;overflow:auto}
.ph-item{padding:10px 12px;cursor:pointer;font-size:14px}
.ph-item:hover{background:#f3f5f7}
.ph-empty{padding:10px 12px;color:#888;font-size:13px}
button{width:100%;padding:12px;border:none;border-radius:6px;color:#fff;font-weight:bold;cursor:pointer;margin-bottom:10px;font-size:15px}
.btn-login{background:#007bff}
.res-box{display:none;margin-top:15px}
.res-content{background:#1e1e1e;color:#fff;padding:15px;border-radius:8px;font-size:13px;word-break:break-all;font-family:Consolas}
.msg-box{text-align:center;font-size:14px;margin-top:10px;padding:10px;border-radius:6px;display:none}
.msg-err{background:#fee;color:#c00;border:1px solid #fcc}
.msg-succ{background:#e8f5e9;color:#2e7d32;border:1px solid #c8e6c9}
.btn-send{background:#28a745}
</style>
</head>
<body>

<div class="box">
<h3>联通 Token 在线获取助手(魔改版)</h3>

<div class="notice">
  <div class="notice-title">公告</div>
  <div class="notice-text">功能：短信验证码登录，支持腾讯验证码校验、发送验证码与登录。</div>
  <div class="notice-text">支持本地缓存记住手机号</div>
  <div class="notice-text">输出格式：手机号#验证码#token_online#ecs_token#appid</div>
</div>

<div class="ph-wrap">
  <input type="tel" id="ph" placeholder="手机号" maxlength="11" autocomplete="off">
  <div id="ph-suggest" class="ph-suggest"></div>
</div>
<div style="display:flex;gap:12px;margin-bottom:8px">
  <label style="font-size:13px"><input type="radio" name="amode" value="random" checked> 随机 appid</label>
  <label style="font-size:13px"><input type="radio" name="amode" value="custom"> 自定义 appid</label>
</div>
<input id="adv" placeholder="自定义 appid（可选）">
<input type="text" id="cd" placeholder="短信验证码" maxlength="6">

<button class="btn-login" id="lb" onclick="login()">立即登录</button>

<button class="btn-send" id="sb" onclick="sendCode()">发送验证码</button>
<div id="msg" class="msg-box"></div>

<div id="res" class="res-box">
<div class="msg-succ">✅ 登录成功</div>
<div id="res-html" class="res-content"></div>
<textarea id="res-raw" style="display:none"></textarea>
<textarea id="res-simple-raw" style="display:none"></textarea>

<button style="background:#28a745;width:100%" onclick="copy()">复制完整数据</button>
<button style="background:#ff9800;width:100%;margin-top:8px" onclick="copySimple()">复制 token_online#appid</button>

</div>

</div>

<script>
const CAPTCHA_APPID = "195809716";

const PHONE_HISTORY_KEY = "phone_history";
const PHONE_HISTORY_MAX = 20;

function normalizePhone(value){
    return (value || '').replace(/[^0-9]/g, '').slice(0, 11);
}

function loadPhoneHistory(){
    try{
        const raw = localStorage.getItem(PHONE_HISTORY_KEY);
        const list = raw ? JSON.parse(raw) : [];
        if(!Array.isArray(list)) return [];
        return list.filter(v => typeof v === 'string' && v.length > 0);
    }catch(e){
        return [];
    }
}

function savePhoneHistory(phone){
    try{
        const p = normalizePhone(phone);
        if(p.length !== 11) return;
        let list = loadPhoneHistory();
        list = [p, ...list.filter(v => v !== p)];
        if(list.length > PHONE_HISTORY_MAX) list = list.slice(0, PHONE_HISTORY_MAX);
        localStorage.setItem(PHONE_HISTORY_KEY, JSON.stringify(list));
    }catch(e){
        return;
    }
}

function renderPhoneSuggest(list){
    const box = document.getElementById('ph-suggest');
    if(!box) return;
    box.innerHTML = '';
    if(!list.length){
        const empty = document.createElement('div');
        empty.className = 'ph-empty';
        empty.textContent = '无历史记录';
        box.appendChild(empty);
        box.style.display = 'block';
        return;
    }
    list.forEach(v=>{
        const item = document.createElement('div');
        item.className = 'ph-item';
        item.dataset.value = v;
        item.textContent = v;
        box.appendChild(item);
    });
    box.style.display = 'block';
}

function updatePhoneSuggest(keyword){
    const list = loadPhoneHistory();
    const key = normalizePhone(keyword);
    const filtered = key ? list.filter(v => v.includes(key)) : list;
    renderPhoneSuggest(filtered);
}

function hidePhoneSuggest(){
    const box = document.getElementById('ph-suggest');
    if(!box) return;
    box.style.display = 'none';
    box.innerHTML = '';
}

function initPhoneHistory(){
    const input = document.getElementById('ph');
    const box = document.getElementById('ph-suggest');
    if(!input || !box) return;

    box.addEventListener('mousedown', function(e){
        const item = e.target.closest('.ph-item');
        if(item){
            input.value = item.dataset.value || '';
            hidePhoneSuggest();
        }
    });

    input.addEventListener('input', function(){
        updatePhoneSuggest(input.value);
    });
    input.addEventListener('focus', function(){
        updatePhoneSuggest(input.value);
    });
    input.addEventListener('blur', function(){
        setTimeout(hidePhoneSuggest, 150);
    });
}

function generateAppId(){
    try{
        function rnd(){
            return String(Math.floor(Math.random()*10));
        }
        return (
            rnd() + "f" + rnd() + "af" +
            rnd() + rnd() + "ad" +
            rnd() + "912d306b5053abf90c7ebbb695887bc" +
            "870ae0706d573c348539c26c5c0a878641fcc0d3e90acb9be1e6ef858a" +
            "59af546f3c826988332376b7d18c8ea2398ee3a9c3db947e2471d32a49612"
        );
    }catch(e){
        return "";
    }
}

function getAppIdMode(){
    let el=document.querySelector('input[name="amode"]:checked');
    return el ? el.value : 'random';
}
function getAppId(){
    let adv=document.getElementById('adv');
    if(!adv) return '';
    let mode=getAppIdMode();
    if(mode==='random' && !adv.value){
        adv.value = generateAppId();
    }
    return adv.value || '';
}
function syncAppIdInput(){
    let mode=getAppIdMode();
    let adv=document.getElementById('adv');
    if(!adv) return;
    adv.disabled = (mode !== 'custom');
    if(mode === 'random'){
        adv.value = generateAppId();
    }
}
function initAppIdMode(){
    let radios=document.querySelectorAll('input[name="amode"]');
    radios.forEach(r=>r.addEventListener('change', syncAppIdInput));
    syncAppIdInput();
}
initAppIdMode();
initPhoneHistory();

async function sendCode(){
    let p=document.getElementById('ph').value;
    let appid=getAppId();
    let msg=document.getElementById('msg');
    let sb=document.getElementById('sb');

    msg.style.display='none';

    if(!p){
        showMsg('请填写手机号','err');
        return;
    }

    savePhoneHistory(p);

    sb.disabled=true;
    sb.innerText='发送中...';

    try{
        let r=await fetch('/api/send',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({phone:p,appid:appid,resultToken:''})
        });

        let d=await r.json();

        if(d.status==='success'){
            showMsg(d.msg||'验证码已发送','succ');
        }else if(d.status==='need_captcha'){
            showMsg(d.msg||'需要安全验证','err');
            await startCaptcha(p,appid,d.mobile||'');
        }else{
            showMsg(d.msg||'发送失败','err');
        }

    }catch(e){
        showMsg('网络错误','err');
    }

    sb.disabled=false;
    sb.innerText='发送验证码';
}

async function startCaptcha(phone, appid, mobileHex){
    if(typeof TencentCaptcha!=='function'){
        showMsg('验证码组件未加载','err');
        return;
    }

    let captcha = new TencentCaptcha(CAPTCHA_APPID, async function(res){
        if(res.ret===0){
            try{
                let vr=await fetch('/api/validate',{
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({ticket:res.ticket,randstr:res.randstr,mobile:mobileHex,phone:phone,appid:appid})
                });
                let vd=await vr.json();
                if(vd.status==='success' && vd.resultToken){
                    let sr=await fetch('/api/send',{
                        method:'POST',
                        headers:{'Content-Type':'application/json'},
                        body:JSON.stringify({phone:phone,appid:appid,resultToken:vd.resultToken})
                    });
                    let sd=await sr.json();
                    if(sd.status==='success'){
                        showMsg(sd.msg||'验证码已发送','succ');
                    }else{
                        showMsg(sd.msg||'发送失败','err');
                    }
                }else{
                    showMsg(vd.msg||'安全验证失败','err');
                }
            }catch(e){
                showMsg('网络错误','err');
            }
        }else{
            showMsg('已取消安全验证','err');
        }
    });
    captcha.show();
}

async function login(){
    let p=document.getElementById('ph').value;
    let c=document.getElementById('cd').value;
    let appid=getAppId();
    let msg=document.getElementById('msg');
    let resBox=document.getElementById('res');
    let lb=document.getElementById('lb');

    msg.style.display='none';
    resBox.style.display='none';

    if(!p||!c){
        showMsg('请填写手机号和验证码','err');
        return;
    }

    savePhoneHistory(p);

    lb.disabled=true;
    lb.innerText='正在登录...';

    try{
        let r=await fetch('/api/login',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({phone:p,code:c,appid:appid})
        });

        let d=await r.json();

        if(d.status==='success'){

            document.getElementById('res-html').innerText = d.full;
            document.getElementById('res-raw').value = d.full;

            // 自动切割生成 token_online#appid
            try{
                let parts = d.full.split('#');

                if(parts.length >= 5){
                    let simple = parts[2] + "#" + parts[4];
                    document.getElementById('res-simple-raw').value = simple;
                }else{
                    document.getElementById('res-simple-raw').value = "";
                }

            }catch(e){
                document.getElementById('res-simple-raw').value = "";
            }

            resBox.style.display='block';
        }
        else{
            showMsg(d.msg,'err');
        }

    }catch(e){
        showMsg('网络错误','err');
    }

    lb.disabled=false;
    lb.innerText='立即登录';
}

function showMsg(t,type){
    let m=document.getElementById('msg');
    m.innerText=t;
    m.className='msg-box '+(type==='err'?'msg-err':'msg-succ');
    m.style.display='block';
}

function copy(){
    let t=document.getElementById('res-raw');
    t.style.display='block';
    t.select();
    document.execCommand('copy');
    t.style.display='none';
    alert('已复制到剪贴板');
}
function copySimple(){
    let t=document.getElementById('res-simple-raw');

    if(!t.value){
        alert('数据格式异常');
        return;
    }

    t.style.display='block';
    t.select();
    document.execCommand('copy');
    t.style.display='none';
    alert('已复制 token_online#appid');
}

</script>

</body>
</html>
'''
    return render_template_string(html_template)


@app.route('/api/send', methods=['POST'])
def send_code():
    """Handle SMS code sending"""
    try:
        data = request.get_json()
        
        phone = data.get("phone", "")
        appid = data.get("appid", "")
        result_token = data.get("resultToken", "")

        if not phone:
            return jsonify({"status": "fail", "msg": "手机号不能为空"})
        
        if not appid:
            return jsonify({"status": "fail", "msg": "appid 不能为空"})

        # Get or generate device ID from session
        device_id = session.get("deviceId", "")
        if not device_id:
            device_id = ''.join(random.choices('0123456789abcdef', k=32))
            session["deviceId"] = device_id

        u = UnicomAndroid(phone, appid, DEFAULT_APPID, device_id)
        res = u.send_code(result_token)

        code = res["data"].get("code", "") if "data" in res else ""
        dsc = res["data"].get("dsc", res["data"].get("rsp_desc", "") if "data" in res else "")
        
        need_captcha = False
        if code in ["ECS99998", "ECS99999"]:
            need_captcha = True
        if "ECS1164" in dsc:
            need_captcha = True

        if need_captcha:
            if "mobile" in res["data"]:
                session["mobileHex"] = res["data"]["mobile"]
            return jsonify({
                "status": "need_captcha",
                "msg": dsc or "需要安全验证",
                "mobile": res["data"].get("mobile", ""),
                "url": res["data"].get("url", "")
            })

        return jsonify(res)

    except Exception as e:
        return jsonify({"status": "fail", "msg": "服务端内部错误"})


@app.route('/api/validate', methods=['POST'])
def validate_captcha():
    """Handle Tencent CAPTCHA validation"""
    try:
        data = request.get_json()
        
        ticket = data.get("ticket", "")
        randstr = data.get("randstr", "")
        mobile_hex = data.get("mobile", "")
        phone = data.get("phone", "")
        appid = data.get("appid", "")

        if not ticket or not randstr:
            return jsonify({"status": "fail", "msg": "ticket/randstr 不能为空"})

        if not mobile_hex and "mobileHex" in session:
            mobile_hex = session["mobileHex"]

        if not mobile_hex:
            return jsonify({"status": "fail", "msg": "mobile 不能为空"})

        # Get or generate device ID from session
        device_id = session.get("deviceId", "")
        if not device_id:
            device_id = ''.join(random.choices('0123456789abcdef', k=32))
            session["deviceId"] = device_id

        if not appid:
            return jsonify({"status": "fail", "msg": "appid 不能为空"})

        u = UnicomAndroid(phone, appid, DEFAULT_APPID, device_id)
        res = u.validate_tencent_captcha(mobile_hex, ticket, randstr)

        if "code" in res and str(res["code"]) == "0000":
            token = res.get("data", {}).get("resultToken", "")
            if token:
                session["resultToken"] = token
            return jsonify({
                "status": "success",
                "resultToken": token,
                "data": res
            })

        msg = res.get("msg", res.get("dsc", res.get("desc", "校验失败")))
        return jsonify({"status": "fail", "msg": msg, "data": res})

    except Exception as e:
        return jsonify({"status": "fail", "msg": "服务端内部错误"})


@app.route('/api/login', methods=['POST'])
def login():
    """Handle login with phone and code"""
    try:
        data = request.get_json()
        
        phone = data.get("phone", "")
        code = data.get("code", "")
        appid = data.get("appid", "")

        if not phone or not code:
            return jsonify({"status": "fail", "msg": "手机号和验证码不能为空"})
        
        if not appid:
            return jsonify({"status": "fail", "msg": "appid 不能为空"})

        u = UnicomAndroid(phone, appid, DEFAULT_APPID)
        result = u.login(code)
        
        return jsonify(result)

    except Exception as e:
        return jsonify({"status": "fail", "msg": "服务端内部错误"})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)