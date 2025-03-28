
import threading

class event_read():
    def __init__(self):
        self.event = None
        self.isRunning = True

    def event_handler(self):
        while (self.isRunning):
            print("do something")

class event_write():
    def __init__(self):
        self.event = None
        
    def event_trigger(self):
        self.event.set()
        self.event.clear()

event = threading.Event()

e_write = event_write()
e_read = event_read()
e_read.event = e_write.event = event

e_write.event_trigger()