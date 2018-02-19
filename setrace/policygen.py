from sys import stderr, stdout

from setools import SELinuxPolicy
from setools.policyrep.exception import InvalidType

from setrace.cmd import SETraceCommand


class SETracePolicyGen(SETraceCommand):
    def __init__(self, loaded_policy: SELinuxPolicy):
        self.loaded_policy = loaded_policy

    def unique_id(self, prefix):
        for idx in range(2 ** 32 - 1):
            uniqid = "%s_%d" % (prefix, idx)
            try:
                self.loaded_policy.lookup_type_or_attr(uniqid)
            except InvalidType:
                return uniqid
        raise RuntimeError("Unable to find a unique id for prefix %s" % prefix)

    def run(self, args):
        if not args.source and not args.target:
            print("Must specify either a source or target type", file=stderr)
            exit(1)

        if args.permissive and not args.source:
            print("Must specify a source type when using --permissive")
            exit(1)

        if args.file:
            output = open(args.file, mode="w")
        else:
            output = stdout

        all_types_id = self.unique_id("all_types")
        class_permission_id = self.unique_id("all_permissions")

        source_type = args.source or all_types_id
        target_type = args.target or all_types_id
        classes = args.security_class or self.loaded_policy.classes()
        class_permissions = map(lambda c: "(classpermissionset %s (%s (all)))" % (class_permission_id, c), classes)

        if output is not stdout:
            print("Writing generated trace policy to %s" % args.file, file=stdout)

        with output as output_fp:
            if args.permissive:
                print("(typepermissive %s)" % source_type, file=output_fp)
            print("(typeattribute %s)" % all_types_id, file=output_fp)
            print("(typeattributeset %s all)" % all_types_id, file=output_fp)
            print("(classpermission %s)" % class_permission_id, file=output_fp)
            print("(auditallow %s %s %s)" % (source_type, target_type, class_permission_id), file=output_fp)
            print("\n".join(class_permissions), file=output_fp)
