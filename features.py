def extract_features(packet):
    try:
        return [len(packet), packet.proto, packet.sport, packet.dport, packet.ttl]
    except:
        return None