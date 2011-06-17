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
import keyring
import string

from curses.textpad import Textbox
from BeautifulSoup import SoupStrainer, BeautifulSoup, BeautifulStoneSoup

from googlevoice import Voice

class _Textbox(Textbox):
  """ curses.textpad.Textbox requires users to ^g on completion, which is sort
  of annoying for an interactive chat client such as this, which typically only
  reuquires an enter. This subclass fixes this problem by signalling completion
  on Enter as well as ^g. """
  def __init__(*args, **kwargs):
    Textbox.__init__(*args, **kwargs)

  def do_command(self, ch):
    if ch == 10: # Enter
      return 0
    return Textbox.do_command(self, ch)

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
  """ Implements an ncurses chat client. It has two windows on the
  virtual screen: one for displaying chat history and one for
  entering text. As this interface matures, I may split it out and
  make an XMPP backend for it as well, since mcabber doesn't support
  MUC. """
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
    """ Redraw the window with the current history. """
    (rows, cols) = self.chatscreen.getmaxyx()

    for (row, line) in zip(range(len(self.history)), self.history):
      self.chatscreen.addstr(row, 0, line) 
      self.chatscreen.clrtoeol()

    self.chatscreen.refresh()

  def user_input(self):
    """ Get some user input and return it. """
    cmd = self.textpad.edit()
    self.entryscreen.clear()
    # strip the newlines out of the middle of the words
    cmd = string.replace(cmd, '\n', '')
    # remove unprintable characters
    return ''.join(c if c in string.printable else '' for c in cmd)

  @synchronized("curses_lock")
  def message(self, who, what):
    """ Add a message to the history. """
    (rows, cols) = self.chatscreen.getmaxyx()

    def message_lines(message):
      words = message.split()
      accum = words[0]
      words = words[1:]
      while len(words) > 0:
        while True: 
          accum += " "
          # if the word is too huge to fit on the screen, split it
          # into parts
          if len(words[0]) > cols:
            first_part = words[0][:cols - len(accum)]
            words[0] = words[0][len(first_part):]
            accum += first_part
          elif len(accum) + len(words[0]) < cols:
            # otherwise, just grab this word off the front
            accum += words[0]
            words = words[1:]
          # have we filled up accum? are we out of stuff to print?
          if len(accum) >= cols or len(words) == 0:
            break
        yield accum
        accum = "   "

    for line in message_lines(who+': '+what):
      self.history.append(line)

    if len(self.history) > rows:
      self.history = self.history[-rows:]

class GVChat(Chat):
  """ Implements a google voice chat client. """
  def __init__(self, user, password):
    self.gv = Voice()
    self.gv.login(user, password)

    Chat.__init__(self)

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

    divs = SoupStrainer('div')
    tree = BeautifulSoup(data, parseOnlyThese=divs)

    # We need to know who to send texts to, as that information is
    # not included with each message.
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
      msgitem["text"] = BeautifulStoneSoup(msgitem["text"],
                            convertEntities=BeautifulStoneSoup.HTML_ENTITIES
                          ).contents[0]
      self.smses.append(msgitem)
    
    # Now that we have the SMSes, we can add their text and render them.
    for sms in self.smses:
      self.message(sms["from"][:-1], sms["text"])

  def timedupdate(self, timeout):
    """ Update the display now and fire this method again in
    `timeout' seconds. """
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
  passwd = None
  import gnomekeyring
  try:
    # if the user has a keyring password, try to get it, otherwise, prompt them.
    passwd = keyring.get_password('gmail', GOOGLE_VOICE_USERNAME)
  except gnomekeyring.IOError:
    pass
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
