# What is coshell? #
I work remotely, and spend 99% of my time on the command-line. I hate WebEx, LiveMeeting, VNC, etc... I wrote coshell so I could more easily collaborate with my remote co-workers.

Coshell is a wonderfully simple command-line tool that allows you to literally share a terminal with many remote users. This is useful for training, code review, demonstrations, cooperative debugging, etc...

# Download coshell #
Since coshell is a standalone .py file, I figure I'll just keep it simple for now. Just download the latest revision from subversion here, http://coshell.googlecode.com/svn/trunk/coshell.py. Coshell requires python 2.4 or greater.

# Getting Started #
To get started, download coshell.py and start a coshell server like so:
```
chrismd@home $ ./coshell.py --server
Listening on port 3608
Wait for clients to connect, then press 's' to begin shell...

s) start shell  l) list clients p) toggle control privileges for a client
```

Then have your friends download coshell.py as well, and have them connect to you like so:
```
joe@work $ ./coshell.py your.hostname.here
Welcome joe, the following clients are connected
1) joe [192.168.10.42]
```

Now by default coshell will only allow joe to watch whats going on, but if you really trust him you can hit 'p', then '1

&lt;enter&gt;

', to grant him control privileges, like so:

```
joe [192.168.10.42] has connected
<press p>
Enter a client number and press enter
<press 1 followed by enter>
Toggling control privileges for client 1) joe [192.168.10.42]

[ 1 client connected ]
1) joe [192.168.10.42] [privileged]

s) start shell  l) list clients p) toggle control privileges for a client
```

Notice that joe now has `[privileged]` by his name, that means he will be able to interact with the shell along with you. Now to actually start the shell, simply press 's'. Enjoy coshell!

If you want to try coshell out by yourself first, just open two terminals. In the first run "./coshell.py --server, and in the second run "./coshell.py localhost".

# Security Disclaimer #
**NOTE**: coshell is **not encrypted or authenticated**! Why? Because that's non-trivial to write into coshell, but it is trivial to achieve by using ssh to get everyone on the same LAN. Use coshell on a trusted LAN **only**. After you start a shared shell, all tty output will go across the network to each connected client in plain text.

Also note that in theory it should be totally possible to run coshell securely on an untrusted network if tunneled over ssh. I have not tried this yet, but when I do I will publish a simple script for doing so.

# Uh, why not just use GNU screen? #
Believe it or not, when I wrote coshell I did not know screen supported this functionality. Either way, coshell still fills a niche in being very small, simple, and trivial to deploy (it doesn't even require curses). But if all of your parties have screen installed and know how to use screen, then its probably a better choice.