import argparse

from setools import SELinuxPolicy

from setrace.analyzer import SETraceAnalyzer
from setrace.policygen import SETracePolicyGen


class SETrace(object):
    def __init__(self, policy: SELinuxPolicy):
        self.policy = policy

    def run(self):
        def selinux_type(value):
            return str(self.policy.lookup_type_or_attr(value))

        def selinux_class(value):
            return str(self.policy.lookup_class(value))

        parser = argparse.ArgumentParser(prog="setrace", description="A utility for tracing SELinux access vector "
                                                                     "checks")
        subparsers = parser.add_subparsers(dest="cmd_name")
        polgen_parser = subparsers.add_parser("polgen")
        polgen_parser.add_argument("-s", "--source", type=selinux_type,
                                   help="The source type to use in auditallow statements for the generated "
                                        "trace policy.")
        polgen_parser.add_argument("-t", "--target", type=selinux_type,
                                   help="The target type to use in auditallow statements for the generated "
                                        "trace policy.")
        polgen_parser.add_argument("-o", "--output-file", dest="file",
                                   help="Path to a file to store the generated policy in.")
        polgen_parser.add_argument('-c', '--class', type=selinux_class, action='append', dest="security_class",
                                   help="Override the list of security classes that will be audited by "
                                        "the trace policy.  Can be specified multiple times.")
        polgen_parser.add_argument('-p', '--permissive', action="store_true", help="Generate a 'typepermissive' "
                                                                                   "statement for the source type "
                                                                                   "when emitting the trace policy.  "
                                                                                   "Can only be used when --source is "
                                                                                   "present.")
        analyze_parser = subparsers.add_parser("analyze")
        analyze_parser.add_argument("-i", "--input-file", dest="file", help="The input log to analyze",
                                    default="/var/log/audit/audit.log")
        analyze_parser.add_argument("-p", "--process-id", dest="pid", help="Filter audit logs by a process ID.")
        analyze_parser.add_argument("-f", "--follow", dest="follow", action="store_true",
                                    help="Tail the audit log and continuously analyze new entries (requires root).")
        analyze_parser.set_defaults(follow=False)
        args = parser.parse_args()

        if args.cmd_name == "polgen":
            cmd = SETracePolicyGen(self.policy)
        elif args.cmd_name == "analyze":
            cmd = SETraceAnalyzer()
        else:
            parser.print_help()
            return

        cmd.run(args)


def main():
    # We need a policy available to validate SELinux type identifiers.  @todo: factor that out to the individual command
    setrace = SETrace(SELinuxPolicy())
    setrace.run()


if __name__ == "__main__":
    main()
