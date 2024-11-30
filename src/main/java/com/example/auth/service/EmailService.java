package com.example.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendResetPasswordEmail(String to, String resetToken) throws MessagingException, IOException {
        // Generate the reset URL dynamically
        String resetUrl = "http://localhost:3000/reset-password?token=" + resetToken;

        // Load the email template
        String template = loadEmailTemplate("templates/reset-password-email.html");

        // Replace {{resetLink}} in the template with the actual reset URL
        String emailContent = template.replace("{{resetLink}}", resetUrl);

        // Create a MIME message
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setTo(to);
        helper.setSubject("Reset Your Password");
        helper.setText(emailContent, true);  // Set content to HTML

        // Send the email
        mailSender.send(message);
    }

    private String loadEmailTemplate(String path) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ClassPathResource(path).getInputStream()))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
}
