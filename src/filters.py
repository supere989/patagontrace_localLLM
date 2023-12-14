def pcap_to_txt(input_file, protocol):
    field_commands = {
        "sip": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e sip.Method '
            '-e sip.Call-ID '
            '-e sip.From '
            '-e sip.To '
            '-e sip.CSeq '
            '-e sip.Via '
            '-e sip.Contact '
            '-e sip.User-Agent '
            '-e udp.srcport '
            '-e udp.dstport '
        ),
        "diameter": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e diameter.Session-Id '
            '-e diameter.Origin-Host '
            '-e diameter.Origin-Realm '
            '-e diameter.Destination-Host '
            '-e diameter.Destination-Realm '
            '-e diameter.cmd.code '
            '-e diameter.Result-Code '
            '-e diameter.applicationId  '
            '-e diameter.flags.request '
        ),
        "sigtran": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e sctp.srcport '
            '-e sctp.dstport '
            '-e sctp.verification_tag '
            '-e m3ua.message-class '
            '-e m3ua.message-type '
            '-e m3ua.affected-point-code '
        ),
        "gtp": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e gtp.message_type '
            '-e gtp.teid '
        ),
        # Add other protocols if needed
    }
