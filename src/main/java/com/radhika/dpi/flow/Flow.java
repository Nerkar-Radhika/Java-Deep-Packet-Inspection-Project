package com.radhika.dpi.flow;

public class Flow {

    public String sourceIP;
    public String destinationIP;

    public int sourcePort;
    public int destinationPort;

    public String protocol;

    public int packetCount;
    public long totalBytes;

    public long firstSeen;
    public long lastSeen;

    public String service;
    public boolean alertShown = false;
}