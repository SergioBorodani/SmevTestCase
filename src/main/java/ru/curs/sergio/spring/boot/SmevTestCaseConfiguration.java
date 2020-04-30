package ru.curs.sergio.spring.boot;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import ru.curs.sergio.spring.boot.properties.SmevTestCaseProperties;

@Configuration
@EnableConfigurationProperties({SmevTestCaseProperties.class})
public class SmevTestCaseConfiguration {
    public SmevTestCaseConfiguration() {
    }
}
