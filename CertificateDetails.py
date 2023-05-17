import ssl
import socket
import OpenSSL

def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context() 
    # By using create_default_context(), you get a context that is preconfigured with reasonable default settings for secure SSL/TLS communication.
    
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    # In the provided code, the wrap_socket() method is used to wrap the conn socket object (created using socket.create_connection()) with SSL/TLS encryption. 

    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)
    # It is used to convert a certificate from DER (Distinguished Encoding Rules) format to PEM (Privacy-Enhanced Mail) format.
    # Binary to Human Readable format

site = input("Enter website url: ")
certificate = get_certificate(f'{site}')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
# print(dir(x509))

issuerComponents = x509.get_issuer().get_components()

issuer_country = issuerComponents[0][1].decode("UTF-8")
issuer_org = issuerComponents[1][1].decode("UTF-8")
issuer_common_name = issuerComponents[2 ][1].decode("UTF-8")
# print(issuerComponents)


print("\nIssuer Details: \n")
print(f"Issuer country name is:\t {issuer_country}")
print(f"Issuer organization name is:\t {issuer_org}")
print(f"Issuer common name is:\t {issuer_common_name}")


Startdate = (x509.get_notBefore().decode("UTF-8"))
Issued_On = Startdate[6:8] + "/" + Startdate[4:6] + "/" + Startdate[0:4] 

Enddate = (x509.get_notAfter().decode("UTF-8"))
Expires_On = Enddate[6:8] + "/" + Enddate[4:6] + "/" + Enddate[0:4] 


print("\nValidity: \n")
print(f"Issued on:\t {Issued_On}")
print(f"Expires on:\t {Expires_On}")