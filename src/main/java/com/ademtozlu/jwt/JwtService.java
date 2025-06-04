package com.ademtozlu.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {

    private static final String SECRET_KEY = "YkROlZoCA0UAypjJy2aJ+ZHdGym6MZtdaL8VW5nFv6U=";

    public String generateToken(UserDetails userDetails) {
        Map<String, String> claimsMap = new HashMap<>();
        claimsMap.put("role", "ADMIN");
     return  Jwts.builder()
       .setSubject(userDetails.getUsername())
       .setClaims(claimsMap)
       .setIssuedAt(new Date())
       .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2)) 
       .signWith(getKey(), SignatureAlgorithm.HS256)
       .compact();
}

public <T> T exportToken(String token, Function<Claims, T> claimsFunction) {
    Claims claims = Jwts
    .parserBuilder()
    .setSigningKey(getKey())
    .build()
    .parseClaimsJws(token).getBody();

    return claimsFunction.apply(claims);
}

public String getUsernameByToken(String token){
  return  exportToken(token, Claims::getSubject);
}

public boolean isTokenExpired(String token){
    Date expiredDate = exportToken(token, Claims::getExpiration);
    return new Date().before(expiredDate);
    //Wenn die aktuelle Zeit vor dem Ablaufdatum liegt, ist das Token noch gültig.
}

public Key getKey() {
  byte[] keyBytes =  Decoders.BASE64.decode(SECRET_KEY);
  return Keys.hmacShaKeyFor(keyBytes);
}}