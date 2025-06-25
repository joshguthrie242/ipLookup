import requests
import certifi

def lookup_ip(ip):  
    print(f"Using CA bundle: {certifi.where()}")

    url = f"https://api.iplocation.net/?ip={ip}"
    try:
        response = requests.get(url, verify='/etc/ssl/certs/ZscalerRootCA.crt')
        response.raise_for_status()
        print(response.text)
    except requests.exceptions.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    
    lookup_ip('172.56.164.98')
