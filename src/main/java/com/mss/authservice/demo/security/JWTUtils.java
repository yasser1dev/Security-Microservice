package com.mss.authservice.demo.security;

public class JWTUtils {

    public static final String SECRET="myHMACPrivateKey";
    public static final String HEADER="Authorization";
    public static final String PREFIX="Bearer ";
    public static final long DATE_EXP_ACCESS_TOKEN=2*60*1000;
    public static final long DATE_EXP_REFRESH_TOKEN=4*24*3600*1000;
}
