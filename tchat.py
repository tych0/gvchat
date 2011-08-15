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
import itertools

from curses.textpad import Textbox
from BeautifulSoup import SoupStrainer, BeautifulSoup, BeautifulStoneSoup

from googlevoice import Voice
from googlevoice.util import LoginError

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

  CHATBOX_SIZE = 3

  def __init__(self):
    self.curses_lock = threading.Lock()

    self.global_screen = curses.initscr()
    (globaly, globalx) = self.global_screen.getmaxyx()
    curses.noecho()
    # one row for status bar, and CHATBOX_SIZE rowsd for the chatbox
    self.chatscreen = curses.newwin(globaly-Chat.CHATBOX_SIZE, globalx, 0, 0)
    self.entryscreen = curses.newwin(Chat.CHATBOX_SIZE, globalx, globaly-Chat.CHATBOX_SIZE, 0)

    self.textpad = _Textbox(self.entryscreen, insert_mode=True)
    self.textpad.stripspaces = True
    self.history = []

    self.global_screen.leaveok(True)
    self.chatscreen.leaveok(True)
    self.entryscreen.leaveok(False)

    self.update()

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    curses.nocbreak()
    curses.echo()
    curses.endwin()

  def status(self):
    """ Draw a generic status bar of "-"s. """
    (y, x) = self.chatscreen.getmaxyx()
    self.chatscreen.addstr(y-1, 0, '-' * (x-1))

  @synchronized("curses_lock")
  def update(self):
    """ Redraw the window with the current history. """
    (cursory, cursorx) = self.entryscreen.getyx()
    (rows, cols) = self.chatscreen.getmaxyx()

    def message_lines(message):
      words = message.split()
      accum = words[0]
      words = words[1:]
      while len(words) > 0:
        while True: 
          accum += " "
          if len(words[0]) >= cols - 3:
            # if the word is too huge to fit on the screen (note that
            # there's 3 spaces for padding), split it into parts
            first_part = words[0][:cols - len(accum)]
            words[0] = words[0][len(first_part):]
            accum += first_part
          elif len(accum) + len(words[0]) < cols:
            # otherwise, just grab this word off the front
            accum += words[0]
            words = words[1:]
          else:
            # the word is not too big to fit on the screen, but it
            # is too big for this line
            break
          # have we filled up accum? are we out of stuff to print?
          if len(accum) >= cols or len(words) == 0:
            break
        yield accum
        accum = "  "
    lines = list(itertools.chain(*[message_lines(msg) for msg in self.history]))

    # we can only print up to rows number of lines, and we save the last row
    # for the status bar
    lines = lines[-(rows-1):]

    for (row, line) in zip(range(len(lines)), lines):
      self.chatscreen.addstr(row, 0, line) 
      self.chatscreen.clrtoeol()

    self.status()

    self.entryscreen.move(cursory, cursorx)
    self.entryscreen.cursyncup()
    self.chatscreen.noutrefresh()
    self.entryscreen.noutrefresh()
    curses.doupdate()

  def user_input(self):
    """ Get some user input and return it. """
    cmd = self.textpad.edit()
    self.entryscreen.clear()
    # strip the newlines out of the middle of the words
    cmd = string.replace(cmd, '\n', '')
    # remove unprintable characters
    return (''.join(c if c in string.printable else '' for c in cmd)).strip()

  @synchronized("curses_lock")
  def message(self, who, what):
    """ Add a message to the history. """
    (rows, cols) = self.chatscreen.getmaxyx()
    self.history.append(who+': '+what)

    # We can only display at most rows number of messages, since we display one
    # message on each line. (Note that we may display fewer messages than are
    # in self.history, since messages might be longer than one line and wrap.)
    if len(self.history) > rows:
      self.history = self.history[-rows:]

class GVChat(Chat):
  """ Implements a google voice chat client. """
  def __init__(self, user, password):
    self.gv = Voice()
    self.gv.login(user, password)

    self.response_count_lock = threading.Lock()
    self.response_count = 0
    self.to_phone = None
    self.to_name  = None

    Chat.__init__(self)

    self.timer = None
    self.timedupdate(30)

  @synchronized("response_count_lock")
  def increment_response_count(self):
    self.response_count += 1

  @synchronized("response_count_lock")
  def decrement_response_count(self):
    self.response_count -= 1

  def status(self):
    """ Draw a fancy status bar. It has a * if there are pending google
    requests and lists the chatter's name and phone number. """
    active = '*' if self.response_count > 0 else '-'

    if self.to_phone:
      phone = '(%s) %s - %s' % (self.to_phone[:3], self.to_phone[3:6], self.to_phone[6:])
    else:
      phone = ''

    name = self.to_name if self.to_name else ''
    
    (y, x) = self.chatscreen.getmaxyx()
    form = '{:'+ active +'^' + str(x - 1) + '}'

    status_string = form.format(' %s | %s ' % (name, phone))
    self.chatscreen.addstr(y-1, 0, status_string)

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
      if msgitem["text"]:
        msgitem["text"] = BeautifulStoneSoup(msgitem["text"],
                              convertEntities=BeautifulStoneSoup.HTML_ENTITIES
                            ).contents[0]
        self.smses.append(msgitem)
    
    # Now that we have the SMSes, we can add their text and render them.
    for sms in self.smses:
      name = sms["from"][:-1]
      if name != 'Me':
        self.to_name = name
      self.message(name, sms["text"])

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
  try:
    with GVChat(GOOGLE_VOICE_USERNAME, passwd) as chat:
      while True:
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
            # The number of pending responses.
            chat.increment_response_count()

            # Redraw the status bar to let the user know we're active.
            chat.update()

            chat.sendsms(cmd)
            chat.getsms()

            # No more pending requests
            chat.decrement_response_count()

            # tell the user we've deactivated
            chat.update()

          t = threading.Thread(target=sms_sender_thread)
          t.start()
  except LoginError:
    print 'Login failed.'

if __name__ == "__main__":
  main()
