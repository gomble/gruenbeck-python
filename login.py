import hashlib
import random
import base64
import requests
from urllib.parse import urlencode

class Login:
    def __init__(self, user_agent, config):
        self.user_agent = user_agent
        self.config = config


    def get_code_challenge(self):
        hash_value = ""
        result = ""
        while (
            hash_value == ""
            or "+" in hash_value
            or "/" in hash_value
            or "=" in hash_value
            or "+" in result
            or "/" in result
        ):
            chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            result = "".join(random.choice(chars) for _ in range(64))
            result = base64.b64encode(result.encode()).decode().rstrip("=")
            hash_object = hashlib.sha256(result.encode())
            hash_value = base64.b64encode(hash_object.digest()).decode()[:-1]
        return [result, hash_value]

    def login(self):
        code_verifier, code_challenge = self.get_code_challenge()
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "br, gzip, deflate",
            "Connection": "keep-alive",
            "Accept-Language": "de-de",
            "User-Agent": self.user_agent,
        }
        url = (
            "https://gruenbeckb2c.b2clogin.com/a50d35c1-202f-4da7-aa87-76e51a3098c6/b2c_1a_signinup/oauth2/v2.0/authorize?"
            "x-client-Ver=0.8.0&state=NjkyQjZBQTgtQkM1My00ODBDLTn3MkYtOTZCQ0QyQkQ2NEE5&client_info=1&response_type=code&code_challenge_method=S256&x-app-name=Gr%C3%BCnbeck&x-client-OS=14.3&x-app-ver=1.2.1&scope=https%3A%2F%2Fgruenbeckb2c.onmicrosoft.com%2Fiot%2Fuser_impersonation%20openid%20profile%20offline_access&x-client-SKU=MSAL.iOS&"
            "code_challenge=" + code_challenge +
            "&x-client-CPU=64&client-request-id=F2929DED-2C9D-49F5-A0F4-31215427667C&redirect_uri=msal5a83cc16-ffb1-42e9-9859-9fbf07f36df8%3A%2F%2Fauth&client_id=5a83cc16-ffb1-42e9-9859-9fbf07f36df8&haschrome=1&return-client-request-id=true&x-client-DM=iPhone"
        )

        print (code_challenge)
        response = requests.get(url, headers=headers)
        print("Login step 1")
        print ("url1:" + response.url)
        #print ("###code###")
        #print (response.content)
        #print ("###code###ENDE")
        #6print(response.text)
        
        start = response.text.index("csrf") + 7
        end = response.text.index(",", start) - 1
        csrf = response.text[start:end]
        print ("csrf:" + csrf)
        start = response.text.index("transId") + 10
        #start = response.text.index("transId") + 26
        end = response.text.index(",", start) - 1
        transId = response.text[start:end]
        print ("transid:" + transId)
        start = response.text.index("policy") + 9
        end = response.text.index(",", start) - 1
        policy = response.text[start:end]
        print ("policy:" + policy)
        start = response.text.index("tenant") + 9
        end = response.text.index(",", start) - 1
        tenant = response.text[start:end]
        print ("tenant:" + tenant)
        filtered_cookies = [element.split("; ")[0] for element in response.headers["set-cookie"]]
        print("cookie_raw:" + response.headers["set-cookie"].items())
        #print(response.headers["set-cookie"])
        #filtered_cookies = response.headers["set-cookie"]
        #print (str(filtered_cookies))

        cookie = "; ".join(filtered_cookies)
        #cookie = filtered_cookies
        #print ("cookie:" + cookie)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-CSRF-TOKEN": csrf,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://gruenbeckb2c.b2clogin.com",
            "Cookie": cookie,
            "User-Agent": self.user_agent,
        }
        #print(headers)
        url2 = f"https://gruenbeckb2c.b2clogin.com{tenant}/SelfAsserted?tx={transId}&p={policy}"

        #print("url2:" + url2)
        #print(headers)
        response2 = requests.post(url2, data=urlencode({
            "request_type": "RESPONSE",
            "signInName": self.config['mgUser'],
            "password": self.config['mgPass'],
        }), headers=headers)

        #print("Login step 2")
        #print(response2.content)

        #filtered_cookies = [element.split("; ")[0] for element in response2.headers["set-cookie"]]
        filtered_cookies2 = response2.headers["set-cookie"]
        cookie += "; x-ms-cpim-csrf=" + csrf

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "br, gzip, deflate",
            "Connection": "keep-alive",
            "Accept-Language": "de-de",
            "Cookie": cookie,
            "User-Agent": self.user_agent,
        }
        #print(headers)
        print("Login step 3")
        url3 = f"https://gruenbeckb2c.b2clogin.com{tenant}/api/CombinedSigninAndSignup/confirmed?csrf_token={csrf}&tx={transId}&p={policy}"

        response3 = requests.get(url3, headers=headers)

        print(response3.content)
        print(response3.status_code)
        if response3.status_code == 302:
            if "code" in response3.text:
                start = response3.text.index("code%3d") + 7
                end = response3.text.index(">here") - 1
                code = response3.text[start:end]

                headers = {
                    "Host": "gruenbeckb2c.b2clogin.com",
                    "x-client-SKU": "MSAL.iOS",
                    "Accept": "application/json",
                    "x-client-OS": "14.3",
                    "x-app-name": "Grünbeck",
                    "x-client-CPU": "64",
                    "x-app-ver": "1.2.0",
                    "Accept-Language": "de-de",
                    "client-request-id": "F2929DED-2C9D-49F5-A0F4-31215427667C",
                    "x-ms-PkeyAuth": "1.0",
                    "x-client-Ver": "0.8.0",
                    "x-client-DM": "iPhone",
                    "User-Agent": "Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0",
                    "return-client-request-id": "true",
                }

                url4 = f"https://gruenbeckb2c.b2clogin.com{tenant}/oauth2/v2.0/token"

                response4 = requests.post(url4, data=urlencode({
                    "client_info": "1",
                    "scope": "https://gruenbeckb2c.onmicrosoft.com/iot/user_impersonation openid profile offline_access",
                    "code": code,
                    "grant_type": "authorization_code",
                    "code_verifier": code_verifier,
                    "redirect_uri": "msal5a83cc16-ffb1-42e9-9859-9fbf07f36df8://auth",
                    "client_id": "5a83cc16-ffb1-42e9-9859-9fbf07f36df8",
                }), headers=headers)

                access_token = response4.json()["access_token"]
                refresh_token = response4.json()["refresh_token"]

                return access_token, refresh_token

# Beispielaufruf
user_agent = "Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0"
config = {
    "mgUser": "",
    "mgPass": ""
}

login_instance = Login(user_agent, config)

access_token, refresh_token = login_instance.login()
print("Access Token:", access_token)
print("Refresh Token:", refresh_token)
