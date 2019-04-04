import win32evtlog
import win32event
import win32con
import platform
import re
import pywintypes


from .log_event import LogEvent

DETECTED_OS = None

def detect_current_os():
    global DETECTED_OS

    if not DETECTED_OS is None:
        return DETECTED_OS

    full_string = platform.platform()
    matches = re.finditer(r"\d{1,}", full_string)

    for matchNum, match in enumerate(matches, start=1):
        DETECTED_OS = int(match.group())
        return DETECTED_OS


def test_channel_existence(channel):
    h = win32event.CreateEvent(None, 0, 0, None)
    try:
        win32evtlog.EvtSubscribe(channel, win32evtlog.EvtSubscribeToFutureEvents, SignalEvent=h, Query='*')
    except pywintypes.error as e:
        return False
    return True

def subscribe_and_yield_events(channel, query="*"):
    #SUBSCRIBE
    h = win32event.CreateEvent(None, 0, 0, None)
    s = win32evtlog.EvtSubscribe(channel, win32evtlog.EvtSubscribeToFutureEvents, SignalEvent=h, Query=query)

    #LOOP
    while True:
        while True:
            events = win32evtlog.EvtNext(s, 10)

            if len(events) == 0:
                break
            for event in events:
                raw_xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                er = LogEvent(raw_xml, source_os=detect_current_os())
                if er.is_valid():
                    yield er
                else:
                    print("[ERROR] Parsing error")

        while True:
            #print('waiting...')
            w = win32event.WaitForSingleObjectEx(h, 200, True)
            if w == win32con.WAIT_OBJECT_0:
                break