package com.example.auth.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Base64;

public class GenerateJwtKey {
    public static void main(String[] args) {
        // Génère une clé sécurisée pour HMAC-SHA256
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

        // Encode la clé en Base64
        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());

        // Affiche la clé
        System.out.println("Generated Key (Base64): " + base64Key);
    }
}
