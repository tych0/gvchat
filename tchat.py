#!/usr/bin/env python

"""
 ----------------------------------------------------------------------------
 "THE BEER-WARE LICENSE" (Revision 42):
 <tycho@tycho.ws> wrote this file. As long as you retain this notice you
 can do whatever you want with this stuff. If we meet some day, and you think
 this stuff is worth it, you can buy me a beer in return. Tycho Andersen
 (Shamelessly stolen from: http://people.freebsd.org/~phk/)
 ----------------------------------------------------------------------------
"""

GOOGLE_VOICE_USERNAME = "tycho@tycho.ws"

import threading
import curses
import re
import BeautifulSoup
import keyring

from curses.textpad import Textbox

from googlevoice import Voice

class _Textbox(Textbox):
  """ curses.textpad.Textbox requires users to ^g on completion, which is sort
  of annoying for an interactive chat client such as this, which typically only
  reuquires an enter. This subclass fixes this problem by signalling completion
  on Enter as well as ^g. """
  def __init__(*args, **kwargs):
    Textbox.__init__(*args, **kwargs)

  def edit(self, validate=None):
    """Edit in the window and collect the results. Results are given on Enter
    as well as ^g"""
    while 1:
      ch = self.win.getch()
      if validate:
        ch = validate(ch)
      if not ch:
        continue
      if not self.do_command(ch) or ch == 10: # break on enter
        break
      self.win.refresh()
    return self.gather()

# Since curses is not thread safe and we do curses operations from multiple
# threads, we need to synchronize. This decorator does that.
def synchronized(lock_name):
  """ Synchronization decorator. """

  def wrap(f):
    def new_function(*args, **kw):
      self = args[0]
      lock = getattr(self, lock_name)
      lock.acquire()
      try:
        return f(*args, **kw)
      finally:
        lock.release()
    return new_function
  return wrap

class Chat(object):
  def __init__(self):
    self.curses_lock = threading.Lock()

    global_screen = curses.initscr()
    (globaly, globalx) = global_screen.getmaxyx()
    curses.noecho()
    self.chatscreen = curses.newwin(globaly-3, globalx, 0, 0)
    self.entryscreen = curses.newwin(3, globalx, globaly-3, 0)
    self.textpad = _Textbox(self.entryscreen)
    self.textpad.stripspaces = True
    self.history = []
    self.update()

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    curses.nocbreak()
    curses.echo()
    curses.endwin()

  @synchronized("curses_lock")
  def update(self):
    (cursory, cursorx) = curses.getsyx()
    (rows, cols) = self.chatscreen.getmaxyx()

    for (row, line) in zip(range(len(self.history)), self.history):
      self.chatscreen.addstr(row, 0, line) 
      self.chatscreen.clrtoeol()

    self.chatscreen.refresh()
    curses.setsyx(cursory, cursorx)

  def user_input(self):
    cmd = self.textpad.edit()
    self.entryscreen.clear()
    return cmd.strip()

  @synchronized("curses_lock")
  def message(self, who, what):
    (rows, cols) = self.chatscreen.getmaxyx()

    def message_lines(message):
      words = message.split()
      accum = words[0]
      words = words[1:]
      while len(words) > 0:
        while len(words) > 0 and len(accum) + len(words[0]) + 1 < cols:
          accum += " " + words[0]
          words = words[1:]
        yield accum
        accum = "   "

    for line in message_lines(who+': '+what):
      self.history.append(line)

    if len(self.history) > rows:
      self.history = self.history[-rows:]

  def get_status(self):
    return self._status;

  def set_status(self, status):
    (rows, cols) = self.chatscreen.getmaxyx()

    # trim the status to at most the number of columns
    status = status[:cols]

  status = property(get_status, set_status)

class GVChat(Chat):
  def __init__(self, user, password):
    Chat.__init__(self)

    self.gv = Voice()
    self.gv.login(user, password)
    self.timer = None
    self.to_phone = None
    self.timedupdate(30)

  def getsms(self):
    """ Update the GVChat object with the first SMS thread in your
    SMS box. """

    # We could call voice.sms() directly, but I found this does a rather
    # inefficient parse of things which pegs a CPU core and takes ~50 CPU
    # seconds, while this takes no time at all.
    data = self.gv.sms.datafunc()
    data = re.search(r'<html><\!\[CDATA\[([^\]]*)', data, re.DOTALL).groups()[0]

    divs = BeautifulSoup.SoupStrainer('div')
    tree = BeautifulSoup.BeautifulSoup(data, parseOnlyThese=divs)

    msgtype = str(tree.find("span", attrs={"class": "gc-message-type"}))
    m = re.search('\((\d{3})\) (\d{3})-(\d{4})', msgtype)
    self.to_phone = ''.join(m.groups())

    self.smses = [] 
    # we only want the first conversation
    conversation = tree.find("div", attrs={"id" : True},recursive=False)
    msgs = conversation.findAll(attrs={"class" : "gc-message-sms-row"})
    for row in msgs:
      msgitem = {"id" : conversation["id"]} 
      spans = row.findAll("span", attrs={"class" : True}, recursive=False)
      for span in spans :
        cl = span["class"].replace('gc-message-sms-', '')
        msgitem[cl] = (" ".join(span.findAll(text=True))).strip()
      self.smses.append(msgitem)
    
    # Now that we have the SMSes, we can add their text and render them.
    for sms in self.smses:
      self.message(sms["from"][:-1], sms["text"])

  def timedupdate(self, timeout):
    self.getsms()
    self.update()

    # recycle the timedupdate
    self.timer = threading.Timer(timeout, self.timedupdate, args=[timeout])
    self.timer.start()

  def __exit__(self, type, value, traceback):
    self.timer.cancel()
    self.gv.logout()
    Chat.__exit__(self, type, value, traceback)
  
  def sendsms(self, msg):
    if not self.to_phone:
      raise ValueError("No phone number :-(")
    self.gv.send_sms(self.to_phone, msg)

def main():
  passwd = keyring.get_password('gmail', GOOGLE_VOICE_USERNAME)
  with GVChat(GOOGLE_VOICE_USERNAME, passwd) as chat:
    while True:
      chat.update()
      cmd = chat.user_input()
      if cmd == '/quit':
        break
      if cmd == '/refresh':
        chat.getsms()
      if not cmd.startswith('/'):
        # Spawn a thread to handle sending the SMS and updating the chat
        # screen. This way the UI doesn't block for users when google is being
        # slow to respond :-)
        def sms_sender_thread():
          chat.sendsms(cmd)
          chat.getsms()
          chat.update()
        t = threading.Thread(target=sms_sender_thread)
        t.start()

if __name__ == "__main__":
  main()
