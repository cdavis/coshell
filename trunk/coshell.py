#!/usr/bin/python

import sys, os, pwd, fcntl, struct, cPickle, traceback, signal, atexit
import tty, termios, pty
from select import select
from socket import *

PWENT = pwd.getpwuid( os.geteuid() )
USERNAME = PWENT.pw_name
HOSTNAME = gethostname()
DEFAULT_SHELL = PWENT.pw_shell
DEFAULT_PORT = 3608
CHUNK_SIZE = 8192
INTERRUPT_BYTE = chr(3)


class CoShellServer:
  def __init__(self,shell=DEFAULT_SHELL,address='',port=DEFAULT_PORT):
    self.shell = shell
    self.address = address
    self.port = port
    self.clients = set()
    self.tty = None
    self.child_pid = None

  class ClientConnection:
    id_counter = 1
    def __init__(self,sock,addr):
      self.socket = sock
      self.ip = addr[0]
      self.id = self.id_counter
      self.id_counter += 1
      self.registered = False
      self.tty_input_allowed = False
      self.name = None
      self.send_buffer = ""
      self.recv_buffer = ""
      self.message_queue = []
      self.incoming_message_size = 0

    def register(self,name):
      self.name = name
      self.registered = True

    def fileno(self):
      return self.socket.fileno()

    def buffer_append(self,data):
      self.send_buffer += data

    def buffer_not_empty(self):
      return bool(self.send_buffer)

    def send_data(self):
      sent = self.socket.send(self.send_buffer)
      self.send_buffer = self.send_buffer[sent:]

    def receive_messages(self):
      packet = self.socket.recv(CHUNK_SIZE)
      assert packet, "%s connection lost" % self.name
      self.recv_buffer += packet
      self.__process_recv_buffer()

    def __process_recv_buffer(self):
      if not self.incoming_message_size and len(self.recv_buffer) >= 4:
        header = self.recv_buffer[:4]
        self.recv_buffer = self.recv_buffer[4:]
        self.incoming_message_size = struct.unpack("!L",header)[0]
        assert self.incoming_message_size > 0, "%s sent malformed packet" % self.name
      if self.incoming_message_size and len(self.recv_buffer) >= self.incoming_message_size:
        message_string = self.recv_buffer[:self.incoming_message_size]
        self.recv_buffer = self.recv_buffer[self.incoming_message_size:]
        message_object = cPickle.loads(message_string)
        self.message_queue.append(message_object)
        self.incoming_message_size = 0
        self.__process_recv_buffer()

    def get_messages(self):
      messages = self.message_queue
      self.message_queue = []
      return messages

    def disconnect(self):
      self.socket.close()

    def __str__(self):
      s = '(%d) %s [%s]' % (self.id,self.name,self.ip)
      if self.tty_input_allowed:
        s += ' *'
      return s
    __repr__ = __str__

  #CoShellServer methods
  def run(self):
    listener = socket()
    listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listener.bind( (self.address,self.port) )
    listener.listen(5)
    print "Listening on port %d" % self.port
    print "Wait for clients to connect, then press 's' to begin shell...\n"

    stdin = sys.stdin.fileno()
    stdout = sys.stdout.fileno()
    tty.setcbreak(stdin)
    atexit.register(lambda: os.system("stty sane"))

    toRead, toWrite = set([listener, stdin]), set([stdout])
    shell_started = False
    self.tty_buffer = ""
    self.stdout_buffer = self.user_menu()

    while True:
      try:
        readable,writable = select(toRead,toWrite,[])[:2]

        #Accept new client connections
        if listener in readable:
          (client_sock,addr) = listener.accept()
          client = self.ClientConnection(client_sock,addr)
          self.clients.add(client)
          toRead.add(client)

        #Read pending output from the tty and buffer it to stdout and each ClientConnection
        if self.tty in readable:
          try:
            data = os.read(self.tty, CHUNK_SIZE)
          except:
            print "Shell exitted"
            os.close(self.tty)
            os.wait()
            for client in self.clients:
              client.disconnect()
            return
          self.stdout_buffer += data
          toWrite.add(stdout)
          for client in self.clients:
            client.buffer_append(data)
          toWrite |= self.clients

        #Write pending tty output to stdout
        if stdout in writable:
          if self.stdout_buffer:
            written = os.write(stdout,self.stdout_buffer)
            self.stdout_buffer = self.stdout_buffer[written:]
          if not self.stdout_buffer:
            toWrite.discard(stdout)

        #Write pending user input to the tty
        if self.tty in writable:
          if self.tty_buffer:
            written = os.write(self.tty, self.tty_buffer)
            self.tty_buffer = self.tty_buffer[written:]
          if not self.tty_buffer:
            toWrite.remove(self.tty)

        #The local user has hit a key
        if stdin in readable:
          if not shell_started:
            char = os.read(stdin,1)
            if char == 's': #start the shell
              for client in list(self.clients):
                if not client.registered:
                  client.disconnect()
                  self.clients.discard(client)
                  toRead.discard(client)
              listener.close()
              toRead.discard(listener)
              self.start_shell()
              toRead.add(self.tty)
              shell_started = True
            elif char == 'l': #list client connections
              self.stdout_buffer += self.client_listing() + self.user_menu()
              toWrite.add(stdout)
            elif char == 'p': #toggle input privileges
              #I lazily block the whole event loop on this input
              while True:
                client_num = raw_input("Enter a client number and press enter\n").strip()
                if client_num.isdigit(): break
                print 'Not a valid integer!'
              toggle_id = int(client_num)
              found = False
              for client in self.clients:
                if client.id == toggle_id:
                  print 'Toggling control privileges for client %s' % client
                  client.tty_input_allowed = not client.tty_input_allowed
                  found = True
                  break
              if not found:
                print 'No client with that ID exists'
              #Show 'em the client list & menu again
              self.stdout_buffer += '\n' + self.client_listing() + self.user_menu()
              toWrite.add(stdout)
          else: #Shell already started, its just user tty input
            tty_input = os.read(stdin,CHUNK_SIZE)
            self.tty_buffer += tty_input

        #At this point, both readable and writable *only* consist of client connections
        #so without further ado, let's do all the client I/O
        for client in list(self.clients): #cheap copy
          if client in readable:
            try:
              client.receive_messages()
            except:
              traceback.print_exc()
              client.disconnect()
              self.clients.discard(client)
              toRead.discard(client)
              continue
            for message in client.get_messages():
              self.handle_message(client,message)
            toWrite.add(stdout) #in case we've got output buffered
          if client in writable:
            if client.buffer_not_empty():
              client.send_data()
            else:
              toWrite.discard(client)

          if client.buffer_not_empty():
            toWrite.add(client)

        if self.tty_buffer:
          toWrite.add(self.tty)
      except KeyboardInterrupt:
        self.tty_buffer += INTERRUPT_BYTE
        toWrite.add(self.tty)

  def handle_message(self,client,message):
    if not client.registered:
      if 'registration' not in message:
        client.disconnect()
        return
      client.register( message['registration'] )
      connect_msg = "%s [%s] has connected\n" % (client.name,client.ip)
      self.stdout_buffer += connect_msg
      for other_client in self.clients:
        if other_client is client: continue
        other_client.buffer_append(connect_msg)
      welcome_message = "Welcome %s, the following clients are connected\n%s" % (client.name,self.client_listing())
      client.buffer_append(welcome_message)
      return

    if client.tty_input_allowed:
      if 'tty_input' in message:
        self.tty_buffer += message['tty_input']

  def user_menu(self):
    return 's) start shell\tl) list clients\tp) toggle control privileges for a client\n'

  def start_shell(self):
    (pid,fd) = pty.fork()
    # Child becomes the shell
    if pid == 0:
      os.execv(self.shell,[])
      sys.exit(42)
    # Parent
    self.child_pid = pid
    self.tty = fd

  def client_listing(self):
    return '\n'.join( [str(client) for client in self.clients] ) + '\n'


class CoShellClient:
  def __init__(self,server,port=DEFAULT_PORT):
    self.server = server
    self.port = port
    self.tty_write_buffer = ""
    self.socket_send_buffer = ""
    self.socket = None
    self.name = USERNAME

  def run(self):
    self.socket = socket()
    self.socket.connect( (self.server,self.port) )
    self.socket_send_buffer = self.create_message(registration=self.name)

    stdin = sys.stdin.fileno()
    stdout = sys.stdout.fileno()
    tty.setcbreak(stdin)
    atexit.register(lambda: os.system("stty sane"))

    toWrite = set([self.socket])
    while True:
      try:
        readable = select([stdin, self.socket],toWrite,[])[0]

        if stdin in readable:
          data = os.read(stdin,CHUNK_SIZE)
          assert data, "STDIN closed"
          self.socket_send_buffer += self.create_message(tty_input=data)

        if self.socket in readable:
          data = self.socket.recv(CHUNK_SIZE)
          if not data:
            print "Connection closed"
            return
          self.tty_write_buffer += data

        if self.tty_write_buffer:
          written = os.write(stdout,self.tty_write_buffer)
          self.tty_write_buffer = self.tty_write_buffer[written:]
          if self.tty_write_buffer:
            toWrite.add(stdout)
          else:
            toWrite.discard(stdout)

        if self.socket_send_buffer:
          sent = self.socket.send(self.socket_send_buffer)
          self.socket_send_buffer = self.socket_send_buffer[sent:]
          if self.socket_send_buffer:
            toWrite.add(self.socket)
          else:
            toWrite.discard(self.socket)
      except KeyboardInterrupt:
        self.socket_send_buffer += self.create_message(tty_input=INTERRUPT_BYTE)
	toWrite.add(self.socket)

  def create_message(self,**obj):
    data = cPickle.dumps(obj)
    header = struct.pack("!L",len(data))
    packet = header + data
    return packet


if __name__ == '__main__':
  from getopt import getopt

  if len(sys.argv) < 2 or '-h' in sys.argv:
    print '''Usage: %s [options] [server]

Options:
	-p port		Connect to / listen on port
	-h		This help screen
''' % os.path.basename(sys.argv[0])
    sys.exit(1)

  port = DEFAULT_PORT
  (opts,args) = getopt(sys.argv[1:],"p:")
  for opt,val in opts:
    if opt == '-p': port = int(val)

  if args[0] == 'server':
    server = CoShellServer(port=port)
    server.run()
  else:
    client = CoShellClient(args[0],port)
    client.run()
