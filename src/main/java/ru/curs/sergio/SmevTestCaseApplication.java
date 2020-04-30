package ru.curs.sergio;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SmevTestCaseApplication {

    public static void main(String[] args) {
        SpringApplication.run(SmevTestCaseApplication.class, args);
    }

}
