#!/usr/bin/env python
"""Copyright 2008 Chris Davis (chrismd@gmail.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

import sys, os, pwd, fcntl, struct, cPickle, traceback
import errno, signal, atexit
import tty, termios, pty
import socket
from select import select, error as selectError

#Simple python version test
major,minor = sys.version_info[:2]
if major < 2 or (major == 2 and minor < 4):
  version_str = sys.version.split()[0]
  print "You are using python %s, but version 2.4 or greater is required" % version_str
  raise SystemExit(1)

#Global constants
PWENT = pwd.getpwuid( os.geteuid() )
USERNAME = PWENT.pw_name
HOSTNAME = socket.gethostname()
DEFAULT_SHELL = PWENT.pw_shell
DEFAULT_PORT = 3608
CHUNK_SIZE = 8192
INTERRUPT = chr(3)


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
      self.__class__.id_counter += 1
      self.registered = False
      self.tty_input_allowed = False
      self.terminal_size = (0,0)
      self.name = None
      self.send_buffer = ""
      self.recv_buffer = ""
      self.message_queue = []
      self.incoming_message_size = 0

    def register(self,name,rows,cols):
      self.name = name
      self.terminal_size = (rows,cols)
      self.registered = True

    def fileno(self):
      return self.socket.fileno()

    def buffer_message(self,**data):
      message = cPickle.dumps(data)
      header = struct.pack("!L",len(message))
      self.send_buffer += header + message

    def buffer_not_empty(self):
      return bool(self.send_buffer)

    def send_data(self):
      sent = self.socket.send(self.send_buffer)
      self.send_buffer = self.send_buffer[sent:]

    def receive_messages(self):
      packet = self.socket.recv(CHUNK_SIZE)
      assert packet
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
      s = '%d) %s [%s]' % (self.id,self.name,self.ip)
      if self.tty_input_allowed:
        s += ' [privileged]'
      return s
    __repr__ = __str__

  #CoShellServer methods
  def run(self):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        try:
          readable,writable = select(toRead,toWrite,[])[:2]
        except selectError, e:
          if e.args[0] == errno.EINTR: # SIGWINCH causes this
            continue
          raise

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
            for client in self.clients:
              client.disconnect()
            os.close(self.tty)
            os.wait()
            return
          self.stdout_buffer += data
          toWrite.add(stdout)
          for client in self.clients:
            client.buffer_message(tty_input=data)
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
              self.stdout_buffer += self.client_listing() + self.user_menu()
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
              print "Client %s (%s) connection lost" % (client.name,client.ip)
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
        if self.tty is not None:
          self.tty_buffer += INTERRUPT
          toWrite.add(self.tty)
        else:
          print "Exitting coshell"
          raise SystemExit(0)

  def handle_message(self,client,message):
    if not client.registered:
      if 'registration' not in message:
        client.disconnect()
        return
      client.register( **message['registration'] )
      connect_msg = "%s [%s] has connected\n" % (client.name,client.ip)
      self.stdout_buffer += connect_msg + self.user_menu()
      for other_client in self.clients:
        if other_client is client: continue
        other_client.buffer_message(tty_input=connect_msg)
      welcome_message = "Welcome %s, the following clients are connected\n%s" % (client.name,self.client_listing())
      client.buffer_message(tty_input=welcome_message)
      return

    if client.tty_input_allowed:
      if 'tty_input' in message:
        self.tty_buffer += message['tty_input']

    if 'sigwinch' in message:
      client.terminal_size = message['sigwinch']
      self.adjust_window_size()

  def user_menu(self):
    return '\ns) start shell\tl) list clients\tp) toggle control privileges for a client\n'

  def start_shell(self):
    (pid,fd) = pty.fork()
    # Child becomes the shell
    if pid == 0:
      os.execv(self.shell,[self.shell])
      raise SystemExit(42)
    # Parent
    self.child_pid = pid
    self.tty = fd
    self.rows, self.cols = get_window_size(self.tty)
    self.adjust_window_size()

  def client_listing(self):
    plurality = (len(self.clients) > 1 and "s") or ""
    heading = '\n[ %d client%s connected ]\n' % (len(self.clients),plurality)
    listing = '\n'.join( [str(client) for client in sorted(self.clients,key=lambda c: c.id)] )
    return heading + listing + '\n'

  def install_sigwinch_handler(self):
    signal.signal(signal.SIGWINCH, self.sigwinch_handler)

  def remove_sigwinch_handler(self):
    signal.signal(signal.SIGWINCH, signal.SIG_IGN)

  def sigwinch_handler(self,sig,data):
    self.remove_sigwinch_handler()
    self.rows, self.cols = get_window_size(sys.stdin.fileno())
    self.adjust_window_size()
    self.install_sigwinch_handler()

  def adjust_window_size(self):
    row_sizes = [client.terminal_size[0] for client in self.clients]
    row_sizes.append(self.rows)
    col_sizes = [client.terminal_size[1] for client in self.clients]
    col_sizes.append(self.cols)
    new_rows = min(row_sizes)
    new_cols = min(col_sizes)
    if 0 not in (new_rows,new_cols):
      if self.tty is not None:
        set_window_size(self.tty, new_rows, new_cols)
        for client in self.clients:
          client.buffer_message(sigwinch=(new_rows,new_cols))


class CoShellClient:
  def __init__(self,server,port=DEFAULT_PORT):
    self.server = server
    self.port = port
    self.tty_write_buffer = ""
    self.socket_send_buffer = ""
    self.socket = None
    self.name = USERNAME
    self.recv_buffer = ""
    self.incoming_message_size = 0
    self.message_queue = []

  def run(self):
    self.socket = socket.socket()
    self.socket.connect( (self.server,self.port) )
    rows,cols = get_window_size( sys.stdin.fileno() )
    registration_info = dict(name=self.name, rows=rows, cols=cols)
    self.socket_send_buffer = self.create_message(registration=registration_info)

    stdin = sys.stdin.fileno()
    stdout = sys.stdout.fileno()
    tty.setcbreak(stdin)
    atexit.register(lambda: os.system("stty sane"))

    toWrite = set()
    while True:
      if self.socket_send_buffer:
        toWrite.add(self.socket)
      try:
        try:
          readable = select([stdin, self.socket],toWrite,[])[0]
        except selectError, e:
          if e.args[0] == errno.EINTR: #SIGWINCH causes this
            continue
          raise

        if stdin in readable:
          data = os.read(stdin,CHUNK_SIZE)
          assert data, "STDIN closed"
          self.socket_send_buffer += self.create_message(tty_input=data)

        if self.socket in readable:
          try:
            self.receive_messages()
          except:
            print 'Connection closed'
            self.disconnect()
            return
          for message in self.get_messages():
            self.handle_message(message)

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
        self.socket_send_buffer += self.create_message(tty_input=INTERRUPT)
        toWrite.add(self.socket)

  def create_message(self,**obj):
    data = cPickle.dumps(obj)
    header = struct.pack("!L",len(data))
    packet = header + data
    return packet

  def receive_messages(self):
    packet = self.socket.recv(CHUNK_SIZE)
    assert packet
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

  def handle_message(self,message):
    if 'tty_input' in message:
      self.tty_write_buffer += message['tty_input']
    if 'sigwinch' in message:
      (rows,cols) = message['sigwinch']
      self.remove_sigwinch_handler()
      set_window_size(sys.stdin.fileno(), rows, cols)
      self.install_sigwinch_handler()

  def disconnect(self):
    self.socket.close()

  def install_sigwinch_handler(self):
    signal.signal(signal.SIGWINCH, self.sigwinch_handler)

  def remove_sigwinch_handler(self):
    signal.signal(signal.SIGWINCH, signal.SIG_IGN)

  def sigwinch_handler(self,sig,data):
    rows,cols = get_window_size(sys.stdin.fileno())
    self.socket_send_buffer += self.create_message(sigwinch=(rows,cols))


# Dynamic terminal size utilies
def get_window_size(fd):
  zeroes = struct.pack('HHHH', 0, 0, 0, 0)
  size_info = fcntl.ioctl(fd, termios.TIOCGWINSZ, zeroes)
  rows, cols = struct.unpack('HHHH', size_info)[0:2]
  return (rows,cols)

def set_window_size(fd, rows, cols):
  size_info = struct.pack('HHHH', rows, cols, 0, 0)
  fcntl.ioctl(fd, termios.TIOCSWINSZ, size_info)


if __name__ == '__main__':
  from optparse import OptionParser

  option_parser = OptionParser(usage='%prog [options] [hostname]\n')
  option_parser.add_option('-s','--server',action='store_true',default=False,
    help="run a coshell server")
  option_parser.add_option('-p','--port',type='int',default=DEFAULT_PORT,
    help="connect to or listen on the given port")

  (options,args) = option_parser.parse_args()

  if not (options.server or args):
    option_parser.print_usage()
    raise SystemExit(1)

  if options.server:
    coshell = CoShellServer(port=options.port)
  else:
    hostname = args[0]
    coshell = CoShellClient(hostname,port=options.port)
  try:
    coshell.install_sigwinch_handler()
    coshell.run()
    raise SystemExit(0)
  except (socket.error,socket.gaierror), e:
    error_num, error_message = e.args
    print 'Socket error: %s' % error_message
  raise SystemExit(1)
