import os
import pythoncom
import win32com.client

#Queue Access
MQ_RECEIVE_ACCESS	= 0x1,
MQ_SEND_ACCESS	= 0x2,
MQ_PEEK_ACCESS	= 0x20,
MQ_ADMIN_ACCESS	= 0x80

#MQSHARE
MQ_DENY_NONE	= 0,
MQ_DENY_RECEIVE_SHARE	= 1

class MSMQCustom(object):    
    def __init__(self, queue_name):

        computer_name = os.getenv('COMPUTERNAME')
        self.QueueInfo = win32com.client.Dispatch("MSMQ.MSMQQueueInfo")
        self.QueueInfo.PathName = (".\private$\\" + queue_name)
        self.QueueInfo.Label = ("private$\\" + queue_name)
        self.QueueInfo.FormatName = ("direct=os:" + computer_name + "\\PRIVATE$\\" + queue_name)

        self.Message = win32com.client.Dispatch("MSMQ.MSMQMessage")
        self.Queue = win32com.client.Dispatch("MSMQ.MSMQQueue")

    def open_queue(self, MQAccess, MQShareMode):
        try:
            self.Queue = self.QueueInfo.Open(MQAccess, MQShareMode)
            return True
        except Exception as e:
            #print ("Error" + str(e))
            return False

    def close_queue(self):
        if self.Queue:
            self.Queue.Close()

    def send_to_queue(self, label, body):
        self.Message.Label = label
        self.Message.Body = body
        if self.Queue:
            self.Message.Send(self.Queue)
        else:
            print ("Sending Failed")

    def recv_from_queue(self):
        self.Message = self.Queue.Receive()
        return self.Message

    def peek(self, timeout):
        value = self.Queue.Peek(pythoncom.Empty, pythoncom.Empty, timeout)
        return value

    def  clear(self):
        self.Queue.Purge()

    def create(self):
        try:
            self.QueueInfo.Create()
        except Exception as e:
            print ((e.args[2]))
          
def main():
    msmq = MSMQCustom("Test1111")
    # msmq.create()
    # msmq.open_queue(2, 0)
    # msmq.send_to_queue("Test", "Test")

#------------------------------
main()