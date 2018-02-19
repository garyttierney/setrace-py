import auparse
import os
import time

from setrace.cmd import SETraceCommand


class SETraceRecordReducer(object):
    def fold(self, fields: dict, info: dict):
        raise NotImplementedError


class AvcRecordReducer(SETraceRecordReducer):
    def fold(self, fields: dict, info: dict):
        pass


class SyscallRecordReducer(SETraceRecordReducer):
    def fold(self, fields: dict, info: dict):
        pass


AVC_REDUCER = AvcRecordReducer()
SYSCALL_REDUCER = SyscallRecordReducer()

RECORD_REDUCERS = {
    'AVC': AVC_REDUCER,
    'USER_AVC': AVC_REDUCER,
    'SYSCALL': SYSCALL_REDUCER
}


class SETraceEventField(object):
    def __init__(self, name, value, interp):
        self.name = name
        self.value = value
        self.interp = interp


class SETraceEvent(object):
    def __init__(self, event_id):
        self.record_id = event_id


class SETraceAnalyzer(SETraceCommand):
    def __init__(self):
        self.running = True

    def run(self, args):
        def parser_callback(au, cb_event_type, event_list: list):
            if cb_event_type != auparse.AUPARSE_CB_EVENT_READY:
                return

            if not au.first_record():
                return

            info = {}

            while True:
                type_name = au.get_type_name()
                if type_name not in RECORD_REDUCERS:
                    au.next_record()
                    continue

                record_fields = {}
                au.first_field()

                while True:
                    field_name = au.get_field_name()
                    field_str = au.get_field_str()
                    interp = au.interpret_field()
                    record_fields[field_name] = SETraceEventField(field_name, field_str,
                                                                  interp)
                    if not au.next_field():
                        break

                reducer = RECORD_REDUCERS[type_name]
                reducer.fold(record_fields, info)

                if not au.next_record():
                    break

            event_list.append(info)

        event_list = []
        parser = auparse.AuParser(auparse.AUSOURCE_FEED, None)
        parser.add_callback(parser_callback, event_list)
        parser_hungry = True

        with open(args.file, 'r') as input_fd:
            if args.follow:
                input_fd.seek(0, os.SEEK_END)

            while self.running:
                data = input_fd.readline()
                if not data:
                    if not args.follow: break
                    if parser_hungry:
                        parser.feed("\n")  # Parsers love new-lines
                        parser_hungry = False

                    time.sleep(1)
                    continue

                parser.feed(data)
                parser_hungry = True
