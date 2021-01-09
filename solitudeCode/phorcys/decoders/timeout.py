import signal
import time
from mitmproxy import ctx
from colorama import Fore


class TimeOutException(Exception):
    pass


def alarm_handler(signum, frame):
    ctx.log.info(Fore.RED + "ALARM signal received")
    raise TimeOutException()


def loop(n):
    for sec in range(n):
        ctx.log.info(Fore.RED + "sec {}".format(sec))
        time.sleep(1)


signal.signal(signal.SIGALRM, alarm_handler)
signal.alarm(8)

try:
    loop(6)
except TimeOutException as ex:
    ctx.log.info(Fore.RED + str(ex))
signal.alarm(0)

loop(6)
