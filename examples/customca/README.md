# CustomCA

This example shows you how to use a custom CA to sign the HTTPS MITM
requests (you can use your own generated certificates).
If the client has some kind of SSL pinning to check the TLS certificates, all
the request will most likely fail, so make sure to remove it before using
this proxy or opening new issues.

Proxy server will generate a custom certificate for the target host, for each
request, and it's used to read the request data of an HTTPS
connection.
The client will establish a TLS connection using the generated certificate
with the proxy server, the server will read the request data, process it
according to the user needs, and then it will do a new request to the real
destination.

The CA certificate must be trusted by your system, or the client will reject
the connection, since it's not recognized.

## Trust CA certificate
GoProxy does not ship a shared CA private key. Package initialization loads a
persistent CA from `goproxy.LoadOrCreateDefaultCA()` when its default
user-configuration directory is writable, and otherwise generates an ephemeral
CA for the current process.

Export `goproxy.CA_CERT` to a local `ca.pem` file and trust that file. For a
server deployment, generate and retain an independent CA in a protected
directory:

```go
ca, err := goproxy.LoadOrCreateCA("/etc/goproxy/ca.pem", "/etc/goproxy/key.pem")
if err != nil {
    log.Fatal(err)
}
mitm := &goproxy.ConnectAction{
    Action:    goproxy.ConnectMitm,
    TLSConfig: goproxy.TLSConfigFromCA(ca),
}
```

The private key is written with mode `0600`; back it up and protect it like
any other root CA key. Do not trust the historical `ca.pem` from older GoProxy
source trees, because its matching private key was published in the source.

### Use your certificate
You can also use an existing CA and trust its certificate instead. Replace
`ca.pem` in the following instructions with your CA certificate filename.
You can generate your own self-signed certificate with
[openssl](https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl).

### Firefox
You have to reach the certificate manager configuration in order to add
the certificate to the trusted ones.
To reach it, open the settings and type in search bar "Certificates", then
click on the button "View Certificates...".
In the tab "Authorities", click "Import..." and select the `ca.pem` file.
GoProxy CA is now trusted by your browser!

### Chrome
Open the certificate manager configuration:
> "Settings" > "Privacy and Security" > "Security" > "Manage certificates"

Go to the tab "Authorities", click "Import" and select the `ca.pem` file.
GoProxy CA is now trusted by your browser!

### System
If you want the root certificate to be trusted by all applications in your
environment, consider adding it to the system trusted certificates.
Here is a couple of guides about how to do it, but we don't provide any support:
- [1](https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html)
- [2](https://unix.stackexchange.com/questions/90450/adding-a-self-signed-certificate-to-the-trusted-list)

#### MkCert
Do you want a managed, easy to use solution that automatically generates
a root CA certificate for local usage, and automatically adds it to the trusted system
certificates? Consider [MkCert](https://github.com/FiloSottile/mkcert).
It's enough to just use it and add the generated trusted certificate to GoProxy.
