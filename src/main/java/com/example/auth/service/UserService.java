package com.example.auth.service;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public String generateResetToken(User user) {
        String token = UUID.randomUUID().toString();
        user.setResetToken(token);
        userRepository.save(user); // Ensure the token is saved
        return token;
    }



    public Optional<User> findByResetToken(String resetToken) {
        return userRepository.findByResetToken(resetToken);
    }

    public void resetPassword(User user, String newPassword) {
        user.setPassword(newPassword);
        user.setResetToken(null);
        userRepository.save(user);
    }

}
