package com.radhika.dpi.security;

import java.util.HashSet;
import java.util.Set;

public class PortScanInfo {

    public int packets = 0;

    public Set<Integer> ports = new HashSet<>();

    public Set<Integer> synPorts = new HashSet<>();

    public Set<Integer> finPorts = new HashSet<>();

    public Set<Integer> nullPorts = new HashSet<>();

    public Set<Integer> xmasPorts = new HashSet<>();

    public int alerts = 0;
}