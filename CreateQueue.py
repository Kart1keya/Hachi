import os
from utils.MSMQCustom import MSMQCustom
from utils.config import Config

def main():
    opts = Config().read_config()
    if "QUEUE_NAME" in opts["config"]:

        # Create Event Queue
        event_queue_name = opts["config"]["QUEUE_NAME"]
        print(event_queue_name)
        msmqueue = MSMQCustom(event_queue_name)
        if msmqueue.open_queue(1, 0):
            print("[!] '%s': Queue already exists" % (event_queue_name))
            msmqueue.close_queue()
        else:
            msmqueue.create()
            print("[+] '%s': Queue created Successfully" % (event_queue_name))


if __name__ == '__main__':
    main()